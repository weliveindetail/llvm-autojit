#include "AutoJITRuntime.h"
#include "AutoJITConfig.h"

#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

#include "tpde-llvm/LLVMCompiler.hpp"

#include <algorithm>
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
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      g_autojit_debug = true;
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

sys::DynamicLibrary dlopenHostProcess() {
  std::string ErrMsg;
  auto Exe = sys::DynamicLibrary::getPermanentLibrary(nullptr, &ErrMsg);
  if (!Exe.isValid()) {
    errs() << "autojit-runtime: Failed to dlopen main executable: " << ErrMsg
           << "\n";
    exit(1);
  }
  return Exe;
}

static std::string extractGUID(const char *Path) {
  std::string Stem = std::filesystem::path(Path).stem().string();
  auto Sep = Stem.find('_');
  if (Sep == std::string::npos) {
    errs() << "autojit-runtime: Invalid lazy module path: " << Path << "\n";
    exit(1);
  }
  return Stem.substr(Sep + 1);
}

static std::string createGUID(Twine SourcePath) {
  // Generate MD5 hash of the source path
  MD5 Hasher;
  Hasher.update(SourcePath.str());
  MD5::MD5Result Hash;
  Hasher.final(Hash);

  // Convert to hex string
  SmallString<32> Result;
  MD5::stringifyResult(Hash, Result);
  return Result.str().str();
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

std::string promoteUnique(Twine FuncName, Twine ModuleGUID) {
  return (FuncName + "$llvm_autojit_module_" + ModuleGUID).str();
}

void preprocessFuncDefinition(Function &F, StringRef ModuleGUID) {
  // Keep calling original function frame in static code
  auto OriginalName = F.getName();
  F.setName(promoteUnique(OriginalName, ModuleGUID));

  Function *ProxyFunc =
      Function::Create(F.getFunctionType(), Function::ExternalLinkage,
                       OriginalName, F.getParent());
  F.replaceAllUsesWith(ProxyFunc);

  // Inject unique symbol for implementation
  if (F.getLinkage() != GlobalValue::ExternalLinkage) {
    F.setLinkage(GlobalValue::ExternalLinkage);
    AUTOJIT_DEBUG(dbgs() << "Promoting linkage for lazy function "
                         << F.getName() << "\n");
  }
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

  // FIXME: SourcePath alone isn't reliable
  std::string ModuleGUID = createGUID(SourcePath);
  for (Function &F : *M) {
    if (!F.isDeclaration())
      preprocessFuncDefinition(F, ModuleGUID);
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
    initializeAutoJITDebug();
    auto Exe = dlopenHostProcess();

    LLJITBuilder B;
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

    auto J = B.create();
    if (!J) {
      errs() << "autojit-runtime: Failed to create JIT: " << J.takeError()
             << "\n";
      exit(1);
    }

    auto &JD = (*J)->getMainJITDylib();
    auto FindAllSyms = orc::DynamicLibrarySearchGenerator::SymbolPredicate();
    JD.addGenerator(std::make_unique<DynamicLibrarySearchGenerator>(
        std::move(Exe), (*J)->getDataLayout().getGlobalPrefix(), FindAllSyms,
        nullptr));

    AUTOJIT_DEBUG({
      (*J)->getIRTransformLayer().setTransform(
          [](ThreadSafeModule TSM,
             MaterializationResponsibility &R) -> Expected<ThreadSafeModule> {
            auto Err = TSM.withModuleDo([&](Module &M) -> Error {
              for (Function &F : M)
                if (!F.isDeclaration())
                  dbgs() << "Adding lazy function to JIT: " << F.getName()
                         << "\n";
              return Error::success();
            });
            if (Err)
              return std::move(Err);
            return std::move(TSM);
          });
    });

    for (const char *Path : g_registered_modules) {
      if (!g_materialized.contains(Path)) {
        loadModule(**J, Path);
        g_materialized.insert(Path);
      }
    }

    g_jit = std::move(*J);
  }

  return *g_jit;
}
} // namespace

extern "C" void __llvm_autojit_materialize(const char *FuncName,
                                           const char *FilePath,
                                           void **FuncPtrAddr) {
  if (!FuncName || !FilePath || !FuncPtrAddr) {
    errs() << "autojit-runtime: Invalid parameters\n";
    exit(1);
  }

  std::lock_guard<std::mutex> Lock(g_materialize_mutex);
  initializeLLVM();

  LLJIT &JIT = initializeAutoJIT();
  if (!g_materialized.contains(FilePath)) {
    loadModule(JIT, FilePath);
    g_materialized.insert(FilePath);
  }

  // Look up the function symbol
  std::string ImplName = promoteUnique(FuncName, extractGUID(FilePath));
  auto FuncSymbol = JIT.lookup(ImplName);
  if (!FuncSymbol) {
    errs() << "autojit-runtime: Function " << FuncName << " not found in "
           << FilePath << " (" << FuncSymbol.takeError() << ")\n";
    exit(1);
  }

  // Get the compiled function pointer
  void *FuncPtr = (void *)FuncSymbol->getValue();
  AUTOJIT_DEBUG(dbgs() << "autojit-runtime: Materialized function " << FuncName
                       << " from " << FilePath << " at address " << FuncPtr
                       << "\n");

  // Patch the pointer that is checked by the function frame in static code
  *FuncPtrAddr = FuncPtr;
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
