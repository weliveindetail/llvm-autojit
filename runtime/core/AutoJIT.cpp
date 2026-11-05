#include "runtime/AutoJITRuntime.h"

#include "common/EHFrames.h"
#include "common/Imports.h"

#include "runtime/core/AutoJIT.h"
#include "runtime/core/ExecutorPlatform.h"

#include <llvm/ADT/SmallSet.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/ExecutionEngine/ObjectCache.h>
#include <llvm/ExecutionEngine/Orc/CompileUtils.h>
#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/IRTransformLayer.h>
#include <llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ObjectLinkingLayer.h>
#include <llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/Compiler.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/SmallVectorMemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/xxhash.h>
#include <llvm/TargetParser/Host.h>
#include <llvm/Support/Process.h>
#include <llvm/ExecutionEngine/Orc/Shared/OrcRTBridge.h>

#include <llvm/ExecutionEngine/Orc/SelfExecutorProcessControl.h>

#if defined(AUTOJIT_ENABLE_TPDE)
#include "tpde-llvm/LLVMCompiler.hpp"
#endif

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

using namespace llvm;
using namespace llvm::orc;

bool g_autojit_debug = false;
bool g_autojit_debug_initialized = false;

#if !defined(NDEBUG)
namespace llvm {
  extern bool DebugFlag;
  extern void setCurrentDebugType(const char *Type);
}
#endif

static ExitOnError ExitOnErr("[autojit-runtime] ");

static bool isEnvVarSet(const char *Name) {
  if (const char *Var = std::getenv(Name)) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      return true;
  }
  return false;
}

void autojit::initializeDebugLog() {
  if (g_autojit_debug_initialized)
    return;
  if (isEnvVarSet("AUTOJIT_DEBUG")) {
    g_autojit_debug = true;
#if !defined(NDEBUG)
    llvm::DebugFlag = true;
    llvm::setCurrentDebugType("orc");
#endif
  }
  g_autojit_debug_initialized = true;
}

static std::string toString(GlobalValue::LinkageTypes LT) {
  switch (LT) {
  case GlobalValue::ExternalLinkage:
    return "extern";
  case GlobalValue::AvailableExternallyLinkage:
    return "available_externally";
  case GlobalValue::LinkOnceAnyLinkage:
    return "linkonce";
  case GlobalValue::LinkOnceODRLinkage:
    return "linkonce_odr";
  case GlobalValue::WeakAnyLinkage:
    return "weak";
  case GlobalValue::WeakODRLinkage:
    return "weak_odr";
  case GlobalValue::AppendingLinkage:
    return "appending";
  case GlobalValue::InternalLinkage:
    return "internal";
  case GlobalValue::PrivateLinkage:
    return "private";
  case GlobalValue::ExternalWeakLinkage:
    return "extern_weak";
  case GlobalValue::CommonLinkage:
    return "common";
  }
  return "<unknown>";
}

#if !defined(NDEBUG)
static StringRef toString(GlobalVariable::UnnamedAddr UA) {
  switch (UA) {
  case GlobalVariable::UnnamedAddr::None:
    return "named_addr";
  case GlobalVariable::UnnamedAddr::Local:
    return "local_unnamed_addr";
  case GlobalVariable::UnnamedAddr::Global:
    return "unnamed_addr";
  }
  return "<unknown>";
}
#endif

static GlobalValue::GUID getFunctionGUID(Twine ModName, Function *F) {
  if (F->hasLinkOnceLinkage())
    return MD5Hash(F->getName());
  auto UniqueName = (ModName + ":" + F->getName()).str();
  return MD5Hash(UniqueName);
}

// Resolves imports in the link graph to the addresses from the import table of
// their lazy module. This bypasses the symbol tables of the ExecutionSession,
// which would add thousands of symbols with dependency tracking per module.
class autojit::ImportResolver : public ObjectLinkingLayer::Plugin {
public:
  void addImports(uint64_t Hash, ArrayRef<uint64_t> Addrs) {
    std::lock_guard<std::mutex> Lock(TablesMutex);
    Tables[Hash].assign(Addrs.begin(), Addrs.end());
  }

  void modifyPassConfig(MaterializationResponsibility &MR,
                        jitlink::LinkGraph &G,
                        jitlink::PassConfiguration &Config) override {
    Config.PrePrunePasses.push_back(
        [this](jitlink::LinkGraph &G) { return resolveImports(G); });
  }

  Error notifyFailed(MaterializationResponsibility &MR) override {
    return Error::success();
  }
  Error notifyRemovingResources(JITDylib &JD, ResourceKey K) override {
    return Error::success();
  }
  void notifyTransferringResources(JITDylib &JD, ResourceKey DstKey,
                                   ResourceKey SrcKey) override {}

private:
  Error resolveImports(jitlink::LinkGraph &G) {
    SmallVector<std::pair<jitlink::Symbol *, uint64_t>, 32> Resolved;
    std::lock_guard<std::mutex> Lock(TablesMutex);
    for (jitlink::Symbol *Sym : G.external_symbols()) {
      StringRef Name = *Sym->getName();
      if (!Name.consume_front("__autojit_imp_"))
        continue;
      uint64_t Hash;
      size_t Index;
      if (Name.size() < 18 || Name.take_front(16).getAsInteger(16, Hash) ||
          Name[16] != '_' || Name.drop_front(17).getAsInteger(10, Index))
        return createStringError(inconvertibleErrorCode(),
                                 "Invalid import " + *Sym->getName());
      auto It = Tables.find(Hash);
      if (It == Tables.end() || Index >= It->second.size())
        return createStringError(inconvertibleErrorCode(),
                                 "Unknown import " + *Sym->getName());
      // Undefined weak symbols stay external and resolve to null
      if (It->second[Index] != 0)
        Resolved.emplace_back(Sym, It->second[Index]);
    }
    for (auto [Sym, Addr] : Resolved)
      G.makeAbsolute(*Sym, ExecutorAddr(Addr));
    return Error::success();
  }

  std::mutex TablesMutex;
  DenseMap<uint64_t, std::vector<uint64_t>> Tables;
};

// Bump this whenever changes in the runtime affect the compiled objects
static constexpr unsigned CacheVersion = 3;

static std::string getCacheStem(StringRef FilePath, uint64_t Hash) {
  StringRef Stem = FilePath;
  if (Stem.ends_with(".ll") || Stem.ends_with(".bc"))
    Stem = Stem.drop_back(3);
  std::string HashStr = utohexstr(Hash, /*LowerCase=*/true, /*Width=*/16);
  return (Stem + "_" + HashStr + "_r" + Twine(CacheVersion)).str();
}

// Imports get module-unique names. They resolve to the addresses from the
// import table, never to other definitions with the same name.
static std::string getImportName(uint64_t Hash, size_t Index) {
  std::string HashStr = utohexstr(Hash, /*LowerCase=*/true, /*Width=*/16);
  return ("__autojit_imp_" + HashStr + "_" + Twine(Index)).str();
}

// Clang enables outline atomics for AArch64 Linux by default. Their helpers
// (e.g. __aarch64_ldadd4_acq_rel) come from libgcc.a or compiler-rt and are
// hidden in each image, so JITed code can't link against them. Emit atomics
// inline instead. The target-features attribute replaces the features of the
// TargetMachine, so we add LSE explicitly if the host has it. Otherwise the
// backend emits LL/SC loops, which work on all cores.
static void disableOutlineAtomics(Module &M) {
  if (!M.getTargetTriple().isAArch64())
    return;
  static const bool HostHasLSE = [] {
    auto Features = sys::getHostCPUFeatures();
    auto It = Features.find("lse");
    return It != Features.end() && It->second;
  }();
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    SmallVector<StringRef, 32> Features;
    if (Attribute A = F.getFnAttribute("target-features"); A.isValid())
      SplitString(A.getValueAsString(), Features, ",");
    if (llvm::is_contained(Features, "-outline-atomics"))
      continue;
    llvm::erase(Features, "+outline-atomics");
    Features.push_back("-outline-atomics");
    if (HostHasLSE && !llvm::is_contained(Features, "-lse"))
      Features.push_back("+lse");
    F.addFnAttr("target-features", join(Features, ","));
  }
}

Expected<ThreadSafeModule>
autojit::AutoJIT::loadModule(StringRef FilePath, uint64_t Hash,
                             size_t NumImports, StringRef CacheStem) const {
  auto Buffer = MemoryBuffer::getFile(FilePath);
  if (!Buffer) {
    LOG() << "Failed to read IR file: " << FilePath << "\n";
    exit(1);
  }
  StringRef Contents = (*Buffer)->getBuffer();
  if (xxh3_64bits(Contents) != Hash)
    return createStringError(
        inconvertibleErrorCode(),
        "Lazy module " + FilePath + " doesn't match the import table of " +
            "its static object. Was it overwritten by another build?");

  // Check if it's a bitcode file by extension
  // The module must be destroyed before its context on early returns
  auto Context = std::make_unique<LLVMContext>();
  std::unique_ptr<Module> M;
  if (FilePath.ends_with(".bc")) {
    // Parsing as bitcode
    auto ModuleOrError =
        parseBitcodeFile(Buffer.get()->getMemBufferRef(), *Context);
    if (!ModuleOrError) {
      LOG() << "Failed to parse bitcode file: " << FilePath << " ("
            << ModuleOrError.takeError() << ")\n";
      exit(1);
    }
    M = std::move(*ModuleOrError);
  } else {
    // Parse as textual IR
    SMDiagnostic Err;
    M = parseIR(Buffer.get()->getMemBufferRef(), Err, *Context);
    if (!M) {
      LOG() << "Failed to parse IR file: " << FilePath << " ("
            << Err.getMessage() << ")\n";
      exit(1);
    }
  }

  std::string SourcePath = M->getSourceFileName();
  DBG() << "Scheduling module for materialization " << FilePath
        << " (source: " << SourcePath << ")\n";
  if (SourcePath.empty()) {
    errs() << "autojit-runtime error: Source path must not be empty\n";
    exit(1);
  }

  // Match the import table from the static object. The plugin collected the
  // imports on the same IR that we loaded.
  SmallVector<std::string, 32> ImportNames;
  forEachImport(*M, [&](GlobalValue &GV) {
    ImportNames.push_back(GV.getName().str());
  });
  if (ImportNames.size() != NumImports)
    return createStringError(inconvertibleErrorCode(),
                             "Lazy module " + FilePath + " has " +
                                 Twine(ImportNames.size()) +
                                 " imports, but its import table has " +
                                 Twine(NumImports));

  disableOutlineAtomics(*M);

  std::unordered_set<Function *> DropFunctions;

  for (Function &F : *M) {
    if (F.isDeclaration())
      continue;
    if (autojit::isStaticInit(F)) {
      DBG() << "Drop " << F.getName() << " (static init)\n";
      DropFunctions.insert(&F);
      F.dropAllReferences();
      continue;
    }
    if (F.hasAvailableExternallyLinkage()) {
      if (F.hasFnAttribute(Attribute::AlwaysInline)) {
        // Mandatory definition that was meant to be inlined in all call-sites
        DBG() << "Keep as internal defintion " << F.getName()
              << " (always-inline with available-externally linkage)\n";
        F.setLinkage(GlobalValue::InternalLinkage);
      } else {
        // Optional definition for cross-module optimization
        DBG() << "Remove optional definition " << F.getName()
              << " (available-externally linkage)\n";
        F.deleteBody();
        continue;
      }
    }
    if (F.hasLocalLinkage()) {
      DBG() << "Keep " << F.getName() << " (local definition)\n";
      continue;
    }

    // Rename our JITed definition, so we can find it from the trampoline ID in
    // the static function frame. Linkonce functions exist in many modules.
    // The name is unique for this module, so ORC never discards our copy and
    // the compiled object is the same, no matter which modules we loaded
    // before. We need that for the object cache.
    std::string OriginalName = F.getName().str();
    GlobalValue::GUID G = getFunctionGUID(SourcePath, &F);
    std::string ImplName = autojit::guidToFnName(G, Hash);
    F.setName(ImplName);
    F.setLinkage(GlobalValue::ExternalLinkage);
    F.setVisibility(GlobalValue::DefaultVisibility);
    F.setComdat(nullptr);

    // Inject a declaration for the original name. The JIT will see it and
    // lookup the symbol in the host process, which has the static function
    // frame with a trampoline into our JITed definition. This keeps function
    // pointers stable.
    DBG() << "Rename lazy definition " << OriginalName << " to " << ImplName
          << "\n";
    Function *ProxyDecl = Function::Create(
        F.getFunctionType(), Function::ExternalLinkage, OriginalName, *M);
    F.replaceAllUsesWith(ProxyDecl);
  }

  if (GlobalVariable *Ctors = M->getNamedGlobal("llvm.global_ctors")) {
    Ctors->eraseFromParent();
  }
  for (Function *F : DropFunctions) {
    F->removeFromParent();
  }

  for (GlobalVariable &GV : M->globals()) {
    if (GV.hasAtLeastLocalUnnamedAddr()) {
      // A private copy for this module, for the same reason as above. The
      // address of unnamed_addr variables is insignificant.
      DBG() << "Keep definiton for " << GV.getName()
            << " (local copy of unnamed_addr)\n";
      if (!GV.isDeclaration() && !GV.hasLocalLinkage()) {
        GV.setLinkage(GlobalValue::InternalLinkage);
        GV.setVisibility(GlobalValue::DefaultVisibility);
        GV.setComdat(nullptr);
      }
      continue;
    }
    DBG() << "Turn into declaration " << GV.getName() << "\n";
    GV.dropAllReferences();
    GV.setComdat(nullptr);
    GV.setInitializer(nullptr);
    GV.setLinkage(GlobalValue::ExternalLinkage);
  }

  SmallSet<GlobalAlias *, 16> DropAliases;
  for (GlobalAlias &GA : M->aliases()) {
    if (GA.hasExternalLinkage() || GA.hasExternalWeakLinkage() ||
        GA.hasWeakODRLinkage()) {
      // Static executable has both, the definition and the alias
      DBG() << "Drop global alias " << GA.getName() << "\n";
      DropAliases.insert(&GA);
      continue;
    }
    [[maybe_unused]] bool RuntimeFixup = false;
    if (auto *AliasFn = dyn_cast<Function>(GA.getAliasee())) {
      if (GA.hasAtLeastLocalUnnamedAddr() &&
          AliasFn->getUnnamedAddr() == GlobalVariable::UnnamedAddr::None) {
        GA.replaceAllUsesWith(AliasFn);
        RuntimeFixup = true;
      }
    }
#if !defined(NDEBUG)
    std::string Info;
    if (auto *AliasFn = dyn_cast<Function>(GA.getAliasee())) {
      raw_string_ostream(Info)
          << toString(GA.getLinkage()) << " " << toString(GA.getUnnamedAddr())
          << " -> " << toString(AliasFn->getLinkage()) << " "
          << toString(AliasFn->getUnnamedAddr());
    } else {
      Info = "no function alias";
    }
    if (RuntimeFixup) {
      DBG() << "Resolve global alias " << GA.getName() << " to "
            << GA.getAliasee()->getName() << " (" << Info << ")\n";
    } else {
      DBG() << "Import global alias " << GA.getName() << " for "
            << GA.getAliasee()->getName() << " (" << Info << ")\n";
    }
#endif
  }

  for (GlobalAlias *GA : DropAliases) {
    GA->replaceAllUsesWith(GA->getAliasee());
    GA->eraseFromParent();
  }

  for (size_t I = 0; I < ImportNames.size(); I += 1) {
    GlobalValue *Decl = M->getNamedValue(ImportNames[I]);
    if (!Decl)
      continue;
    assert(Decl->isDeclaration() && "Imports must be declarations");
    std::string Name = getImportName(Hash, I);
    DBG() << "Import " << ImportNames[I] << " as " << Name << "\n";
    Decl->setName(Name);
    // JITed code is far away from the static code, so it must not access
    // imports PC-relative. The visibility of the declaration has no meaning
    // for the JIT, but hidden and protected symbols must be dso_local.
    Decl->setVisibility(GlobalValue::DefaultVisibility);
    Decl->setDSOLocal(false);
  }

  // The compiler caches the object under this name
  M->setModuleIdentifier(CacheStem);

  bool DebugInfoBroken;
  if (verifyModule(*M, &dbgs(), &DebugInfoBroken)) {
    LOG() << "Bailing out due to broken module " << M->getName()
          << (DebugInfoBroken ? " (with broken debug info)" : " ") << "\n";
    exit(1);
  }

  return ThreadSafeModule(std::move(M), std::move(Context));
}

// Writes compiled lazy modules to the object cache
class autojit::ObjectCacheWriter : public ObjectCache {
public:
  void notifyObjectCompiled(const Module *M, MemoryBufferRef Obj) override {
    // Cached objects live next to their lazy modules
    std::string ObjName = M->getModuleIdentifier() + ".o";
    // We don't want to cache arbitrary LLJIT artifacts
    if (!sys::path::filename(ObjName).starts_with("autojit_"))
      return;
    // The cache is best-effort
    auto Skip = [&](StringRef What, std::error_code EC) {
      DBG() << "Failed to cache " << ObjName << " (" << What
            << "): " << EC.message() << "\n";
    };
    SmallString<128> TmpName;
    int FD;
    if (auto EC =
            sys::fs::createUniqueFile(ObjName + ".tmp%%%%%%", FD, TmpName))
      return Skip("create", EC);
    raw_fd_ostream OS(FD, /*shouldClose=*/true);
    OS << Obj.getBuffer();
    OS.close();
    // Avoid report_fatal_error() in the destructor
    if (OS.has_error()) {
      std::error_code EC = OS.error();
      OS.clear_error();
      sys::fs::remove(TmpName);
      return Skip("write", EC);
    }
    // The cache is multi-thread/process, so we publish atomically. Losing a
    // race to a concurrent writer is fine: their object is equivalent.
    if (auto EC = sys::fs::rename(TmpName, ObjName)) {
      sys::fs::remove(TmpName);
      return Skip("rename", EC);
    }
  }

  // Cached objects are checked in addModule() before we load the IR
  std::unique_ptr<MemoryBuffer> getObject(const Module *M) override {
    return nullptr;
  }
};

#if defined(AUTOJIT_ENABLE_TPDE)
class TPDECompiler : public IRCompileLayer::IRCompiler {
public:
  TPDECompiler(JITTargetMachineBuilder JTMB)
      : IRCompiler(
            llvm::orc::irManglingOptionsFromTargetOptions(JTMB.getOptions())) {
    Compiler = tpde_llvm::LLVMCompiler::create(JTMB.getTargetTriple());
    assert(Compiler != nullptr && "Unknown architecture");
  }

  Expected<std::unique_ptr<MemoryBuffer>> operator()(Module &M) override {
    std::lock_guard<std::mutex> Lock(CompileMutex);
    auto &B = Buffers.emplace_back(std::make_unique<std::vector<uint8_t>>());
    if (!Compiler->compile_to_elf(M, *B)) {
      errs() << "TPDE Failed to compile IR file: " << M.getName() << "\n";
      exit(1);
    }
    StringRef BufferRef{reinterpret_cast<char *>(B->data()), B->size()};
    return MemoryBuffer::getMemBuffer(BufferRef, "", false);
  }

private:
  std::unique_ptr<tpde_llvm::LLVMCompiler> Compiler;
  std::vector<std::unique_ptr<std::vector<uint8_t>>> Buffers;
  std::mutex CompileMutex;
};
#endif

autojit::AutoJIT::~AutoJIT() {
  // Terminate the JIT before static destructors run to avoid races
  if (auto Err = JIT_->getExecutionSession().endSession())
    LOG() << toString(std::move(Err));
}

autojit::AutoJIT::AutoJIT() {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  InitializeNativeTargetAsmParser();
  autojit::initializeDebugLog();
}

Error autojit::AutoJIT::initialize(LLJITBuilder &B) {
  UseObjectCache_ = !isEnvVarSet("AUTOJIT_DISABLE_OBJECT_CACHE");
  B.setPlatformSetUp(autojit::ExecutorPlatform(g_autojit_debug));

  // Threads that materialize different modules compile them concurrently.
  // The compiler creates a TargetMachine for each module.
  if (UseObjectCache_)
    CacheWriter_ = std::make_unique<ObjectCacheWriter>();
  B.CreateCompileFunction = [&](JITTargetMachineBuilder JTMB)
      -> Expected<std::unique_ptr<IRCompileLayer::IRCompiler>> {
    return std::make_unique<ConcurrentIRCompiler>(std::move(JTMB),
                                                  CacheWriter_.get());
  };

  if (isEnvVarSet("AUTOJIT_USE_TPDE")) {
#if defined(AUTOJIT_ENABLE_TPDE)
    B.CreateCompileFunction = [](JITTargetMachineBuilder JTMB)
        -> Expected<std::unique_ptr<IRCompileLayer::IRCompiler>> {
      return std::make_unique<TPDECompiler>(JTMB);
    };
#else
    LOG() << "environment has AUTOJIT_USE_TPDE=On, but "
          << "this runtime does not support it. Either rebuild the "
          << "runtime with AUTOJIT_ENABLE_TPD=On or export "
          << "AUTOJIT_USE_TPDE=Off to use the native LLVM backend\n";
    exit(1);
#endif
  }

  // LLJIT enables this by default with a custom EPC. Then it clones each
  // module into a new context before it compiles it. We don't need that: each
  // of our modules has its own context and we never split them.
  B.setSupportConcurrentCompilation(false);

  auto JTMB = ExitOnErr(JITTargetMachineBuilder::detectHost());
  JTMB.getOptions().EmulatedTLS = false;
  B.setJITTargetMachineBuilder(JTMB);

  JIT_ = ExitOnErr(B.create());

  // Host symbols come from import tables
  auto Resolver = std::make_shared<ImportResolver>();
  Imports_ = Resolver.get();
  cast<ObjectLinkingLayer>(JIT_->getObjLinkingLayer())
      .addPlugin(std::move(Resolver));

#if !defined(NDEBUG)
  JIT_->getIRTransformLayer().setTransform(
      [](ThreadSafeModule TSM,
         MaterializationResponsibility &R) -> Expected<ThreadSafeModule> {
        auto Err = TSM.withModuleDo([&](Module &M) -> Error {
          for (Function &F : M)
            if (!F.isDeclaration())
              DBG() << "Adding lazy function to JIT: " << F.getName() << "\n";
          return Error::success();
        });
        if (Err)
          return std::move(Err);
        return std::move(TSM);
      });
#endif

  return Error::success();
}

// Register EH frames of JITed code with the program's unwinder (see
// common/EHFrames.h). LLVM decides this when it is built and we link our own
// private copy of the unwinder.
static const autojit_eh_frame_registrar_t &getEHFrameRegistrar() {
  static autojit_eh_frame_registrar_t Registrar = [] {
    autojit_eh_frame_registrar_t R;
    if (autojit_find_eh_frame_registrar(&R) == 0)
      DBG() << "Register EH frames with unwinder in " << R.unwinder << "\n";
    else
      DBG() << "No unwinder found in the program, skip EH frames\n";
    return R;
  }();
  return Registrar;
}

static Error registerEHFrames(ExecutorAddrRange EHFrame) {
  autojit_register_eh_frames(&getEHFrameRegistrar(),
                             EHFrame.Start.toPtr<const void *>(),
                             EHFrame.size());
  return Error::success();
}

static Error deregisterEHFrames(ExecutorAddrRange EHFrame) {
  autojit_deregister_eh_frames(&getEHFrameRegistrar(),
                               EHFrame.Start.toPtr<const void *>(),
                               EHFrame.size());
  return Error::success();
}

static autojit::CWFBuffer
registerEHFramesAllocAction(const char *ArgData, size_t ArgSize) {
  using namespace shared;
  return WrapperFunction<SPSError(SPSExecutorAddrRange)>::handle(
             ArgData, ArgSize, registerEHFrames)
      .release();
}

static autojit::CWFBuffer
deregisterEHFramesAllocAction(const char *ArgData, size_t ArgSize) {
  using namespace shared;
  return WrapperFunction<SPSError(SPSExecutorAddrRange)>::handle(
             ArgData, ArgSize, deregisterEHFrames)
      .release();
}

// In-process executor that registers EH frames with the program's unwinder.
class InProcessControl : public SelfExecutorProcessControl {
public:
  using SelfExecutorProcessControl::SelfExecutorProcessControl;

  static Expected<std::unique_ptr<InProcessControl>> Create() {
    auto PageSize = sys::Process::getPageSize();
    if (!PageSize)
      return PageSize.takeError();
#if AUTOJIT_LLVM_21
    auto EPC = std::make_unique<InProcessControl>(
        std::make_shared<SymbolStringPool>(),
        std::make_unique<InPlaceTaskDispatcher>(),
        Triple(sys::getProcessTriple()), *PageSize, nullptr);
    EPC->BootstrapSymbols[rt::RegisterEHFrameSectionAllocActionName] =
        ExecutorAddr::fromPtr(&registerEHFramesAllocAction);
    EPC->BootstrapSymbols[rt::DeregisterEHFrameSectionAllocActionName] =
        ExecutorAddr::fromPtr(&deregisterEHFramesAllocAction);
    EPC->BootstrapSymbols[autojit::GDBRegisterBootstrapName] =
        ExecutorAddr::fromPtr(&llvm_orc_registerJITLoaderGDBWrapper);
#else
    // The default bootstrap symbols include LLVM's GDB JIT registration. C
    // names need no mangling on Linux.
    auto EPC = std::make_unique<InProcessControl>(
        std::make_shared<SymbolStringPool>(),
        std::make_unique<InPlaceTaskDispatcher>(),
        Triple(sys::getProcessTriple()), *PageSize);
    EPC->BootstrapSymbols[rt::RegisterEHFrameSectionAllocActionName.getName()] =
        ExecutorAddr::fromPtr(&registerEHFramesAllocAction);
    EPC->BootstrapSymbols[rt::DeregisterEHFrameSectionAllocActionName
                              .getName()] =
        ExecutorAddr::fromPtr(&deregisterEHFramesAllocAction);
#endif
    return EPC;
  }
};

autojit::AutoJIT &autojit::AutoJIT::get() {
  static std::mutex Setup;
  static ManagedStatic<std::unique_ptr<autojit::AutoJIT>> Instance;

  {
    std::lock_guard<std::mutex> Lock(Setup);
    if (!Instance.isConstructed()) {
      LLJITBuilder Builder;
      Builder.setExecutorProcessControl(ExitOnErr(InProcessControl::Create()));
      *Instance = std::make_unique<AutoJIT>();
      ExitOnErr(Instance->get()->initialize(Builder));
      std::atexit(llvm_shutdown);
    }
  }

  return **Instance;
}

llvm::Error
autojit::AutoJIT::ensureModule(const autojit_lazy_module_t *Module) {
  ModuleState *State;
  {
    std::lock_guard<std::mutex> Lock(ModulesMutex_);
    std::unique_ptr<ModuleState> &Entry = Modules_[Module];
    if (!Entry)
      Entry = std::make_unique<ModuleState>();
    State = Entry.get();
  }

  // Load modules outside of the lock, so threads can load different modules
  // concurrently
  std::call_once(State->Loaded, [&]() {
    const char *FilePath = autojit_lazy_module_path(Module);
    if (Module->version != AUTOJIT_LAZY_MODULE_VERSION) {
      State->Error =
          ("Unsupported descriptor for lazy module " + Twine(FilePath)).str();
      return;
    }
    SmallVector<uint64_t, 32> ImportAddrs;
    ImportAddrs.reserve(Module->num_imports);
    for (uint32_t I = 0; I < Module->num_imports; I += 1)
      ImportAddrs.push_back(autojit_import_address(Module, I));
    if (Error Err = addModule(FilePath, Module->hash, ImportAddrs))
      State->Error = toString(std::move(Err));
  });

  if (!State->Error.empty())
    return createStringError(inconvertibleErrorCode(), State->Error);
  return Error::success();
}

llvm::Error autojit::AutoJIT::addModule(StringRef FilePath, uint64_t Hash,
                                       ArrayRef<uint64_t> ImportAddrs) {
  Imports_->addImports(Hash, ImportAddrs);

  // Cached objects are named after the contents of the lazy module. We don't
  // need the IR then: imports are named by index.
  std::string CacheStem = getCacheStem(FilePath, Hash);
  if (UseObjectCache_) {
    constexpr bool IsText = false;
    constexpr bool RequiresNullTerm = false;
    std::string ObjName = CacheStem + ".o";
    if (auto Obj = MemoryBuffer::getFile(ObjName, IsText, RequiresNullTerm)) {
      DBG() << "Loading module from cache " << ObjName << "\n";
      return JIT_->addObjectFile(std::move(*Obj));
    }
  }

  auto TSM = loadModule(FilePath, Hash, ImportAddrs.size(), CacheStem);
  if (!TSM)
    return TSM.takeError();
  return JIT_->addIRModule(std::move(*TSM));
}

uint64_t autojit::AutoJIT::lookup(const char *Symbol) {
  auto Fn = JIT_->lookup(Symbol);
  if (!Fn) {
    LOG() << toString(Fn.takeError()) << "\n";
    exit(1);
  }

  return Fn->getValue();
}

std::string autojit::guidToFnName(GlobalValue::GUID Guid,
                                  uint64_t ModuleHash) {
  std::string Buffer;
  raw_string_ostream(Buffer)
      << "__autojit_fn_" << Guid << "_"
      << utohexstr(ModuleHash, /*LowerCase=*/true, /*Width=*/16);
  return Buffer;
}
