#include "runtime/AutoJITRuntime.h"
#include "runtime/core/AutoJIT.h"

#include "llvm/ADT/SmallSet.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/ExecutionEngine/ObjectCache.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/DebugObjectManagerPlugin.h"
#include "llvm/ExecutionEngine/Orc/EPCDebugObjectRegistrar.h"
#include "llvm/ExecutionEngine/Orc/EPCDynamicLibrarySearchGenerator.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SmallVectorMemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

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

static std::string getModuleGUID(const std::string &SourcePath) {
  // Generate MD5 hash of the source path
  MD5 Hasher;
  Hasher.update(SourcePath);
  MD5::MD5Result Hash;
  Hasher.final(Hash);

  // Convert to hex string
  SmallString<32> Result;
  MD5::stringifyResult(Hash, Result);
  return Result.str().str();
}

static GlobalValue::GUID getFunctionGUID(Twine ModName, Function *F) {
  if (F->hasLinkOnceLinkage())
    return GlobalValue::getGUID(F->getName());
  auto UniqueName = (ModName + ":" + F->getName()).str();
  return GlobalValue::getGUID(UniqueName);
}

static bool isStaticInit(const Function &F) {
  StringRef FuncName = F.getName();
  if (FuncName.starts_with("_GLOBAL__sub_"))
    return true;
  if (FuncName.starts_with("__cxx_global_var_init"))
    return true;
  return false;
}

static sys::DynamicLibrary dlopenHostProcess() {
  std::string ErrMsg;
  auto Exe = sys::DynamicLibrary::getPermanentLibrary(nullptr, &ErrMsg);
  if (!Exe.isValid()) {
    LOG() << "Failed to dlopen main executable: " << ErrMsg << "\n";
    exit(1);
  }
  return Exe;
}

ThreadSafeModule autojit::AutoJIT::loadModule(StringRef FilePath) const {
  auto Buffer = MemoryBuffer::getFile(FilePath);
  if (!Buffer) {
    LOG() << "Failed to read IR file: " << FilePath << "\n";
    exit(1);
  }

  // Check if it's a bitcode file by extension
  std::unique_ptr<Module> M;
  auto Context = std::make_unique<LLVMContext>();
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

  std::unordered_set<Function *> DropFunctions;

  for (Function &F : *M) {
    if (F.isDeclaration())
      continue;
    if (isStaticInit(F)) {
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
        DropFunctions.insert(&F);
        F.dropAllReferences();
        continue;
      }
    }
    if (F.hasLocalLinkage()) {
      DBG() << "Keep " << F.getName() << " (local definition)\n";
      continue;
    }

    // Rename our JITed definition, so we can find it from the trampoline ID in
    // the static function frame.
    std::string OriginalName = F.getName().str();
    GlobalValue::GUID G = getFunctionGUID(SourcePath, &F);
    std::string ImplName = autojit::guidToFnName(G);
    F.setName(ImplName);

    // Inject a declaration for the original name. The JIT will see it and
    // lookup the symbol in the host process, which has the static function
    // frame with a trampoline into our JITed definition. This keeps function
    // pointers stable.
    DBG() << "Import " << OriginalName << " as " << ImplName << "\n";
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

  // Local definitions get exposed and must not collide
  std::string UniquePostfix = "_autojit_module_" + getModuleGUID(SourcePath);

  for (GlobalVariable &GV : M->globals()) {
    if (GV.hasAtLeastLocalUnnamedAddr()) {
      DBG() << "Keep definiton for " << GV.getName()
            << " (local copy of unnamed_addr)\n";
      continue;
    }
    if (GV.hasWeakLinkage() || GV.hasLinkOnceLinkage()) {
      if (!haveHostSymbol(GV.getName())) {
        DBG() << "Keep definiton for " << GV.getName() << " ("
              << toString(GV.getLinkage())
              << " linkage and no host process symbol)\n";
        continue;
      }
      DBG() << "Matched host process symbol for " << GV.getName() << " ("
            << toString(GV.getLinkage()) << " linkage)\n";
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

  bool DebugInfoBroken;
  if (verifyModule(*M, &dbgs(), &DebugInfoBroken)) {
    LOG() << "Bailing out due to broken module " << M->getName()
          << (DebugInfoBroken ? " (with broken debug info)" : " ") << "\n";
    exit(1);
  }

  return ThreadSafeModule(std::move(M), std::move(Context));
}

class BasicCompiler : public IRCompileLayer::IRCompiler {
public:
  BasicCompiler(JITTargetMachineBuilder JTMB)
      : IRCompiler(options(JTMB)), JTMB(std::move(JTMB)) {
    TM = ExitOnErr(this->JTMB.createTargetMachine());
  }

  Expected<std::unique_ptr<MemoryBuffer>> operator()(Module &M) override {
    SmallVector<char, 0> Buffer;
    compileObject(M, Buffer);

    constexpr bool RequiresNullTerminator = false;
    return std::make_unique<SmallVectorMemoryBuffer>(std::move(Buffer), getObjFileName(M.getModuleIdentifier()),
                                                     RequiresNullTerminator);
  }

protected:
  IRSymbolMapper::ManglingOptions options(const JITTargetMachineBuilder &JTMB) {
    return irManglingOptionsFromTargetOptions(JTMB.getOptions());
  }

  std::string getObjFileName(std::string Name) {
    if (Name.ends_with(".ll") || Name.ends_with(".bc"))
      Name = Name.substr(0, Name.size() - 3);
    return Name + ".o";
  }

  void compileObject(Module &M, SmallVectorImpl<char> &Buffer) {
    if (M.getDataLayout().isDefault())
      M.setDataLayout(TM->createDataLayout());
    MCContext *Ctx;
    legacy::PassManager PM;
    raw_svector_ostream ObjStream(Buffer);
    if (TM->addPassesToEmitMC(PM, Ctx, ObjStream)) {
      LOG() << "Target does not support JIT MC emission\n";
      exit(1);
    }
    PM.run(M);
  }

  JITTargetMachineBuilder JTMB;
  std::unique_ptr<TargetMachine> TM;
};

class CachingCompiler : public BasicCompiler {
public:
  CachingCompiler(JITTargetMachineBuilder JTMB)
      : BasicCompiler(std::move(JTMB)) {}

  Expected<std::unique_ptr<MemoryBuffer>> operator()(Module &M) override {
    constexpr bool IsText = false;
    constexpr bool RequiresNullTerm = false;

    // TODO: verify with input hash
    const char *CacheFileStem = "/tmp/autojit_";
    std::string ObjName = getObjFileName(M.getModuleIdentifier());
    if (ObjName.starts_with(CacheFileStem))
      if (auto Obj = MemoryBuffer::getFile(ObjName, IsText, RequiresNullTerm)) {
        LOG() << "Loading module from cache " << ObjName
              << " (source: " << M.getSourceFileName() << ")\n";
        return std::move(*Obj);
      }

    SmallVector<char, 0> Buffer;
    compileObject(M, Buffer);

    if (ObjName.starts_with(CacheFileStem)) {
      std::error_code EC;
      raw_fd_ostream OS(ObjName, EC, sys::fs::OF_None);
      OS.write(Buffer.data(), Buffer.size());
    }

    return std::make_unique<SmallVectorMemoryBuffer>(std::move(Buffer), ObjName,
                                                     RequiresNullTerm);
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
    auto &B = Buffers.emplace_back();
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
};
#endif

autojit::AutoJIT::~AutoJIT() {
  // Terminate the JIT before static destructors run to avoid races
  if (auto Err = JIT_->getExecutionSession().endSession())
    LOG() << toString(std::move(Err));
}

autojit::AutoJIT::AutoJIT() : HostProcess_(dlopenHostProcess()) {
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  InitializeNativeTargetAsmParser();
  autojit::initializeDebugLog();
}

Error autojit::AutoJIT::initialize(LLJITBuilder &B) {
#if defined(AUTOJIT_ENABLE_ORC_RUNTIME)
  const char *OrcRtStart =
      reinterpret_cast<const char *>(_binary_liborc_rt_start);
  const char *OrcRtEnd = reinterpret_cast<const char *>(_binary_liborc_rt_end);
  StringRef OrcRuntimeData(OrcRtStart, OrcRtEnd - OrcRtStart);
#if !defined(NDEBUG)
  auto MemRngStr = format("[0x%" PRIx64 ", 0x%" PRIx64 "]",
                          reinterpret_cast<uintptr_t>(OrcRtStart),
                          reinterpret_cast<uintptr_t>(OrcRtEnd));
  DBG() << "Install embedded orc-runtime from memory range " << MemRngStr
        << "\n";
#endif
  B.setPlatformSetUp(orc::ExecutorNativePlatform(
      MemoryBuffer::getMemBuffer(OrcRuntimeData, "orc_rt", false)));
#endif

  B.CreateCompileFunction = [&](JITTargetMachineBuilder JTMB)
      -> Expected<std::unique_ptr<IRCompileLayer::IRCompiler>> {
    if (LLVM_UNLIKELY(isEnvVarSet("AUTOJIT_DISABLE_OBJECT_CACHE"))) {
      return std::make_unique<BasicCompiler>(std::move(JTMB));
    }
    return std::make_unique<CachingCompiler>(std::move(JTMB));
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

  auto JTMB = ExitOnErr(JITTargetMachineBuilder::detectHost());
  JTMB.getOptions().EmulatedTLS = false;
  B.setJITTargetMachineBuilder(JTMB);

  JIT_ = ExitOnErr(B.create());

  // LLJIT sets up lookup flags for process symbols to MatchExportedSymbolsOnly.
  // It has caused EPCDynamicLibrarySearchGenerator to discard matched symbols,
  // which failed remote lookup but not in-process lookup. This might be an
  // inconsistency in ORC. The below workaround adds another generator that
  // matches all symbols. This adds another RPC roundtrip, which is suboptimal.
  auto &MainJD = JIT_->getMainJITDylib();
  auto ProcessSymbols = JIT_->getProcessSymbolsJITDylib();
  MainJD.addToLinkOrder(*ProcessSymbols, JITDylibLookupFlags::MatchAllSymbols);

  if (g_autojit_debug) {
    auto &ObjLayer = JIT_->getObjLinkingLayer();
    if (auto *JITLinkObjLayer = dyn_cast<ObjectLinkingLayer>(&ObjLayer)) {
      auto &ES = JIT_->getExecutionSession();
      if (auto StubDebug = createJITLoaderGDBRegistrar(ES)) {
        bool AutoRegisterCode = true;
        if (isEnvVarSet("AUTOJIT_DEBUG_NO_AUTOREGISTER")) {
          // Call __jit_debug_register_code() before debugging into JITed code
          AutoRegisterCode = false;
        }
        constexpr bool RequireDebugSections = false;
        auto Plugin = std::make_unique<DebugObjectManagerPlugin>(
            ES, std::move(*StubDebug), RequireDebugSections, AutoRegisterCode);
        JITLinkObjLayer->addPlugin(std::move(Plugin));
      } else {
        LOG() << "Cannot enable debugger support: "
              << toString(StubDebug.takeError());
      }
    }
  }

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

autojit::AutoJIT &autojit::AutoJIT::get(std::vector<std::string> &NewModules) {
  static std::mutex Setup;
  static std::mutex Register;
  static ManagedStatic<std::unique_ptr<autojit::AutoJIT>> Instance;

  {
    std::lock_guard<std::mutex> Lock(Setup);
    if (!Instance.isConstructed()) {
      LLJITBuilder Builder;
      Builder.setExecutorProcessControl(
          ExitOnErr(SelfExecutorProcessControl::Create()));
      *Instance = std::make_unique<AutoJIT>();
      ExitOnErr(Instance->get()->initialize(Builder));
      std::atexit(llvm_shutdown);
    }
  }

  if (!NewModules.empty()) {
    // We can lock inside the condition here, because it's fine to execute the
    // code below again as long as we don't process modules twice. It might
    // happen a few times at startup, but it's cheaper than the additional
    // locking on every get.
    std::lock_guard<std::mutex> Lock(Register);
    for (const std::string &Path : NewModules) {
      ThreadSafeModule TSM = Instance->get()->loadModule(Path);
      ExitOnErr(Instance->get()->submit(std::move(TSM)));
    }
    NewModules.clear();
  }

  return **Instance;
}

llvm::Error autojit::AutoJIT::submit(llvm::orc::ThreadSafeModule Module) {
  return JIT_->addIRModule(std::move(Module));
}

bool autojit::AutoJIT::haveHostSymbol(StringRef Name) const {
  std::string Tmp(Name.data(), Name.size());
  if (HostSymbolsCache_.contains(Tmp))
    return true;
  if (HostProcess_.getAddressOfSymbol(Tmp.c_str())) {
    HostSymbolsCache_.insert(std::move(Tmp));
    return true;
  }
  return false;
}

uint64_t autojit::AutoJIT::lookup(const char *Symbol) {
  auto Fn = JIT_->lookup(Symbol);
  if (!Fn) {
    LOG() << toString(Fn.takeError()) << "\n";
    exit(1);
  }

  return Fn->getValue();
}

std::string autojit::guidToFnName(GlobalValue::GUID Guid) {
  std::string Buffer;
  raw_string_ostream(Buffer) << "__autojit_fn_" << Guid;
  return Buffer;
}
