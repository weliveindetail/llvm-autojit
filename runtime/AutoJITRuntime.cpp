#include "AutoJITRuntime.h"
#include "AutoJITConfig.h"

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Debugging/DebuggerSupport.h"
#include "llvm/ExecutionEngine/Orc/EPCDynamicLibrarySearchGenerator.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/MemoryBuffer.h"
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

static bool g_autojit_debug = false;
#define AUTOJIT_DEBUG(...)                                                     \
  do {                                                                         \
    if (g_autojit_debug) {                                                     \
      __VA_ARGS__;                                                             \
    }                                                                          \
  } while (false)

#if !defined(NDEBUG)
namespace llvm {
  extern bool DebugFlag;
  extern void setCurrentDebugType(const char *Type);
}
#endif

extern "C" {
extern const unsigned char _binary_liborc_rt_start[];
extern const unsigned char _binary_liborc_rt_end[];
}

namespace {

static std::unique_ptr<LLJIT> g_jit;
static std::unordered_set<const char *> g_materialized;
static std::vector<const char *> g_registered_modules;
static std::mutex g_materialize_mutex;
static bool g_llvm_initialized = false;
static bool g_autojit_debug_initialized = false;

void initializeAutoJITDebug() {
  if (g_autojit_debug_initialized)
    return;
  if (const char *Var = std::getenv("AUTOJIT_DEBUG")) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes") {
      g_autojit_debug = true;
#if !defined(NDEBUG)
      llvm::DebugFlag = true;
      llvm::setCurrentDebugType("orc");
#endif
    }
  }
  g_autojit_debug_initialized = true;
}

void initializeLLVM() {
  if (!g_llvm_initialized) {
    InitializeNativeTarget();
    InitializeNativeTargetAsmPrinter();
    InitializeNativeTargetAsmParser();
    g_llvm_initialized = true;
  }
}

static bool useTPDE() {
  if (const char* Var = std::getenv("AUTOJIT_USE_TPDE")) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      return true;
  }
  return false;
}

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

static GlobalValue::GUID getFunctionGUID(Twine ModName, Twine FuncName) {
  auto UniqueName = (ModName + ":" + FuncName).str();
  return GlobalValue::getGUID(UniqueName);
}

static std::string guidToFnName(GlobalValue::GUID Guid) {
  std::string Buffer;
  raw_string_ostream OS(Buffer);
  OS << "__autojit_fn_" << Guid;
  return OS.str();
}

static bool isStaticInit(const Function &F) {
  StringRef FuncName = F.getName();
  if (FuncName.starts_with("_GLOBAL__sub_"))
    return true;
  if (FuncName.starts_with("__cxx_global_var_init"))
    return true;
  return false;
}

void loadModule(LLJIT &JIT, StringRef FilePath) {
  auto Buffer = MemoryBuffer::getFile(FilePath);
  if (!Buffer) {
    errs() << "autojit-runtime: Failed to read IR file: " << FilePath << "\n";
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
      errs() << "autojit-runtime: Failed to parse bitcode file: " << FilePath
             << " (" << ModuleOrError.takeError() << ")\n";
      exit(1);
    }
    M = std::move(*ModuleOrError);
  } else {
    // Parse as textual IR
    SMDiagnostic Err;
    M = parseIR(Buffer.get()->getMemBufferRef(), Err, *Context);
    if (!M) {
      errs() << "autojit-runtime: Failed to parse IR file: " << FilePath << " ("
             << Err.getMessage() << ")\n";
      exit(1);
    }
  }

  std::string SourcePath = M->getSourceFileName();
  AUTOJIT_DEBUG(
      dbgs() << "autojit-runtime: Scheduling module for materialization "
             << FilePath << " (source: " << SourcePath << ")\n");
  if (SourcePath.empty()) {
    errs() << "autojit-runtime error: Source path must not be empty\n";
    exit(1);
  }

  std::unordered_set<Function *> DropFunctions;

  for (Function &F : *M) {
    if (F.isDeclaration())
      continue;
    if (isStaticInit(F)) {
      AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Drop " << F.getName() << " (static init)\n");
      DropFunctions.insert(&F);
      F.dropAllReferences();
      continue;
    }
    if (F.hasAvailableExternallyLinkage()) {
      AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Drop " << F.getName() << " (dupe for cross-module inlining)\n");
      DropFunctions.insert(&F);
      F.dropAllReferences();
      continue;
    }
    if (F.hasLocalLinkage()) {
      AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Keep " << F.getName() << " (local definition)\n");
      continue;
    }

    // Rename our JITed definition, so we can find it from the trampoline ID in
    // the static function frame.
    std::string OriginalName = F.getName().str();
    GlobalValue::GUID G = getFunctionGUID(SourcePath, OriginalName);
    std::string ImplName = guidToFnName(G);
    F.setName(ImplName);

    if (F.hasHiddenVisibility()) {
      // Hidden definitions generate no (observable) symbols in the static
      // binary. We could synthesize one here, but it's easier to just add an
      // alias.
      AUTOJIT_DEBUG(
          dbgs() << "autojit-runtime: Add "
                 << OriginalName << " alias for " << ImplName << "\n");
      F.setVisibility(GlobalValue::DefaultVisibility);
      GlobalAlias::create(OriginalName, &F);
    } else {
      // Inject a declaration for the original name. The JIT will see it and
      // lookup the symbol in the host process, which has the static function
      // frame with a trampoline into our JITed definition. This keeps function
      // pointers stable.
      AUTOJIT_DEBUG(
          dbgs() << "autojit-runtime: Import "
                << OriginalName << " as " << ImplName << "\n");
      Function *ProxyDecl =
          Function::Create(F.getFunctionType(), Function::ExternalLinkage,
                            OriginalName, *M);
      F.replaceAllUsesWith(ProxyDecl);
    }
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
      AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Keep definiton for " << GV.getName() << " (local copy of unnamed_addr)\n");
      continue;
    }
    AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Turn into declaration " << GV.getName() << "\n");
    GV.dropAllReferences();
    GV.setInitializer(nullptr);
    GV.setLinkage(GlobalValue::ExternalLinkage);
  }

  // Add the module to the JIT
  if (auto Err =
          JIT.addIRModule(ThreadSafeModule(std::move(M), std::move(Context)))) {
    errs() << "autojit-runtime: Failed to add module to JIT: " << Err << "\n";
    exit(1);
  }
}

// TODO: Is tpde_llvm thread-safe? Can we make it concurrent?
class TPDECompiler : public IRCompileLayer::IRCompiler {
public:
  TPDECompiler(JITTargetMachineBuilder JTMB)
      : IRCompiler(
            llvm::orc::irManglingOptionsFromTargetOptions(JTMB.getOptions())) {
    Compiler = tpde_llvm::LLVMCompiler::create(JTMB.getTargetTriple());
    assert(Compiler != nullptr && "Unknown architecture");
  }

  Expected<std::unique_ptr<MemoryBuffer>> operator()(Module &M) override {
    auto Buffer = std::make_unique<std::vector<uint8_t>>();
    if (!Compiler->compile_to_elf(M, *Buffer)) {
      errs() << "autojit-runtime: TPDE Failed to compile IR file: "
             << M.getName() << "\n";
      exit(1);
    }
    StringRef BufferRef{reinterpret_cast<char *>(Buffer->data()),
                        Buffer->size()};
    Buffers.push_back(std::move(Buffer));
    return MemoryBuffer::getMemBuffer(BufferRef, "", false);
  }

private:
  std::unique_ptr<tpde_llvm::LLVMCompiler> Compiler;
  std::vector<std::unique_ptr<std::vector<uint8_t>>> Buffers;
};

LLJIT &initializeAutoJIT() {
  if (!g_jit) {
    ExitOnError ExitOnErr("autojit-runtime: ");
    initializeAutoJITDebug();
    //auto Exe = dlopenHostProcess();

    LLJITBuilder B;
//    auto EPC = SelfExecutorProcessControl::Create();
//    if (LLVM_UNLIKELY(!EPC)) {
//      errs() << "autojit-runtime: Failed to create EPC: " << EPC.takeError()
//             << "\n";
//      exit(1);
//    }
//
//    B.setExecutorProcessControl(std::move(*EPC));

#if defined(AUTOJIT_ENABLE_ORC_RUNTIME)
    const char *OrcRtStart =
        reinterpret_cast<const char *>(_binary_liborc_rt_start);
    const char *OrcRtEnd =
        reinterpret_cast<const char *>(_binary_liborc_rt_end);
    StringRef OrcRuntimeData(OrcRtStart, OrcRtEnd - OrcRtStart);
    AUTOJIT_DEBUG({
      auto MemRngStr = format("[0x%" PRIx64 ", 0x%" PRIx64 "]",
                              reinterpret_cast<uintptr_t>(OrcRtStart),
                              reinterpret_cast<uintptr_t>(OrcRtEnd));
      dbgs()
          << "autojit-runtime: Install embedded orc-runtime from memory range "
          << MemRngStr << "\n";
    });
    B.setPlatformSetUp(orc::ExecutorNativePlatform(
        MemoryBuffer::getMemBuffer(OrcRuntimeData, "orc_rt", false)));
#endif

    if (useTPDE()) {
#if defined(AUTOJIT_ENABLE_TPDE)
      B.CreateCompileFunction = [](JITTargetMachineBuilder JTMB)
          -> Expected<std::unique_ptr<IRCompileLayer::IRCompiler>> {
        return std::make_unique<TPDECompiler>(JTMB);
      };
#else
      errs() << "autojit-runtime: environment has AUTOJIT_USE_TPDE=On, but "
             << "this runtime does not support it. Either rebuild the "
             << "runtime with AUTOJIT_ENABLE_TPD=On or export "
             << "AUTOJIT_USE_TPDE=Off to use the native LLVM backend\n";
      exit(1);
#endif
    }

//    B.setProcessSymbolsJITDylibSetup([&Exe](LLJIT &J) -> Expected<JITDylibSP> {
//      auto &ES = J.getExecutionSession();
//      auto &JD = ES.createBareJITDylib("<Process Symbols>");
//      auto G = std::make_unique<EPCDynamicLibrarySearchGenerator>(ES, Exe.getOSSpecificHandle());
//      if (!G)
//        return G.takeError();
//      JD.addGenerator(std::move(*G));
//      return &JD;
//    });

    auto J = B.create();
    if (!J) {
      errs() << "autojit-runtime: Failed to create JIT: " << J.takeError()
             << "\n";
      exit(1);
    }

    //(*J)->defaultLinkOrder().begin();

    //auto &JD = (*J)->getMainJITDylib();
    //auto FindAllSyms = orc::DynamicLibrarySearchGenerator::SymbolPredicate();
    //JD.addGenerator(std::make_unique<DynamicLibrarySearchGenerator>(
    //    std::move(Exe), (*J)->getDataLayout().getGlobalPrefix(), FindAllSyms,
    //    nullptr));

    ExitOnErr(enableDebuggerSupport(**J));

    AUTOJIT_DEBUG({
      (*J)->getIRTransformLayer().setTransform(
          [](ThreadSafeModule TSM,
             MaterializationResponsibility &R) -> Expected<ThreadSafeModule> {
            auto Err = TSM.withModuleDo([&](Module &M) -> Error {
              for (Function &F : M)
                if (!F.isDeclaration())
                  dbgs() << "autojit-runtime: Adding lazy function to JIT: " << F.getName()
                         << "\n";
              return Error::success();
            });
            if (Err)
              return std::move(Err);
            return std::move(TSM);
          });
    });

    for (const char *Path : g_registered_modules)
      loadModule(**J, Path);

    g_registered_modules.clear();
    g_jit = std::move(*J);
  }

  return *g_jit;
}
} // namespace

extern "C" void __llvm_autojit_materialize(void **GuidInPtrOut) {
  if (!GuidInPtrOut || *GuidInPtrOut == nullptr) {
    errs() << "autojit-runtime: Invalid parameters\n";
    exit(1);
  }

  std::lock_guard<std::mutex> Lock(g_materialize_mutex);
  initializeLLVM();

  LLJIT &JIT = initializeAutoJIT();
  assert(g_registered_modules.empty() && "Modules are registered at startup");

  // Look up the function symbol
  GlobalValue::GUID Guid = reinterpret_cast<uintptr_t>(*GuidInPtrOut);
  std::string ImplName = guidToFnName(Guid);
  auto FuncSymbol = JIT.lookup(ImplName);
  if (!FuncSymbol) {
    errs() << "autojit-runtime: Function " << ImplName << " not found: " << FuncSymbol.takeError() << "\n";
    exit(1);
  }

  // Get the compiled function pointer
  void *FuncPtr = (void *)FuncSymbol->getValue();
  AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Materialized function " << ImplName
                       << " at address " << FuncPtr << "\n");

  // Patch the pointer that is checked by the function frame in static code
  *GuidInPtrOut = FuncPtr;
}

extern "C" void __llvm_autojit_register(const char *FilePath) {
  if (!FilePath) {
    errs() << "autojit-runtime: Invalid FilePath parameter\n";
    return;
  }

  std::lock_guard<std::mutex> Lock(g_materialize_mutex);

  initializeAutoJITDebug();
  AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Registering module " << FilePath
                       << "\n");

  for (const char *RegisteredPath : g_registered_modules)
    if (strcmp(RegisteredPath, FilePath) == 0)
      return;
  g_registered_modules.push_back(FilePath);
}
