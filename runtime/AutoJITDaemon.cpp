#include "AutoJITConfig.h"

#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h"
#include "llvm/ExecutionEngine/Orc/TargetProcess/SimpleRemoteEPCServer.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <unistd.h>

using namespace llvm;
using namespace llvm::orc;

static bool g_autojit_debug = false;

#define AUTOJIT_DEBUG(...) \
  do { \
    if (g_autojit_debug) { \
      __VA_ARGS__; \
    } \
  } while (false)

/* ============================================================================
 * Global JIT State
 * ============================================================================ */

static std::unique_ptr<LLJIT> g_jit;
static std::unique_ptr<SimpleRemoteEPCServer> g_epc_server;
static std::vector<std::string> g_registered_modules;

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static std::string guidToFunctionName(uint64_t Guid) {
  std::string Buffer;
  raw_string_ostream OS(Buffer);
  OS << "__autojit_fn_" << Guid;
  return OS.str();
}

/* ============================================================================
 * Module Loading
 * ============================================================================ */

static void loadModule(LLJIT &JIT, StringRef FilePath) {
  auto Buffer = MemoryBuffer::getFile(FilePath);
  if (!Buffer) {
    errs() << "autojitd: Failed to read IR file: " << FilePath << "\n";
    exit(1);
  }

  SMDiagnostic Err;
  auto Ctx = std::make_unique<LLVMContext>();
  auto M = parseIR(Buffer.get()->getMemBufferRef(), Err, *Ctx);
  if (!M) {
    errs() << "autojitd: Failed to parse IR file: " << FilePath << "\n";
    Err.print("autojitd", errs());
    exit(1);
  }

  AUTOJIT_DEBUG(dbgs() << "autojitd: Loading module " << FilePath << "\n");

  // Add module to JIT
  auto TSM = ThreadSafeModule(std::move(M), std::move(Ctx));
  if (auto Err = JIT.addIRModule(std::move(TSM))) {
    errs() << "autojitd: Failed to add module: " << Err << "\n";
    exit(1);
  }
}

/* ============================================================================
 * JIT Initialization
 * ============================================================================ */

static void initializeJIT() {
  if (g_jit)
    return;

  AUTOJIT_DEBUG(dbgs() << "autojitd: Initializing JIT\n");

  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  InitializeNativeTargetAsmParser();

  // The EPC server is already created in main(), so we use SelfExecutorProcessControl
  // for now. The JIT runs in the daemon process but will be configured to work with
  // the stub as the target via the EPC server's protocol.
  LLJITBuilder Builder;

  auto J = Builder.create();
  if (!J) {
    errs() << "autojitd: Failed to create LLJIT: " << J.takeError() << "\n";
    exit(1);
  }

  // Load all registered modules
  for (const std::string &Path : g_registered_modules) {
    loadModule(**J, Path);
  }

  g_jit = std::move(*J);
  AUTOJIT_DEBUG(dbgs() << "autojitd: JIT initialized\n");
}

/* ============================================================================
 * RPC Interface Implementation
 * ============================================================================ */

extern "C" {

// RPC handler for module registration
shared::CWrapperFunctionResult autojit_rpc_register(const char *ArgData, size_t ArgSize) {
  using SPSArgList = shared::SPSArgList<shared::SPSString>;

  std::string FilePath;
  shared::SPSInputBuffer IB(ArgData, ArgSize);

  if (!SPSArgList::deserialize(IB, FilePath)) {
    return shared::WrapperFunctionResult::createOutOfBandError("Failed to deserialize arguments")
        .release();
  }

  AUTOJIT_DEBUG(dbgs() << "autojitd: RPC register module: " << FilePath << "\n");

  // Store the module path for later loading
  g_registered_modules.push_back(FilePath);

  return shared::WrapperFunctionResult().release();
}

// RPC handler for function materialization
shared::CWrapperFunctionResult autojit_rpc_materialize(const char *ArgData, size_t ArgSize) {
  using SPSArgList = shared::SPSArgList<uint64_t>;
  using SPSRetList = shared::SPSArgList<uint64_t>;

  uint64_t Guid;
  shared::SPSInputBuffer IB(ArgData, ArgSize);

  if (!SPSArgList::deserialize(IB, Guid)) {
    return shared::WrapperFunctionResult::createOutOfBandError("Failed to deserialize arguments")
        .release();
  }

  AUTOJIT_DEBUG(dbgs() << "autojitd: RPC materialize function GUID=0x"
                       << format("%016" PRIx64, Guid) << "\n");

  // Initialize JIT if needed
  initializeJIT();

  // Construct stub function name from GUID
  std::string FuncName = guidToFunctionName(Guid);
  AUTOJIT_DEBUG(dbgs() << "autojitd: Looking up function: " << FuncName << "\n");

  // Look up the function in the JIT
  auto Sym = g_jit->lookup(FuncName);
  if (!Sym) {
    errs() << "autojitd: Failed to lookup function " << FuncName << ": " << Sym.takeError() << "\n";
    return shared::WrapperFunctionResult::createOutOfBandError("Lookup failed").release();
  }

  uint64_t FuncAddr = Sym->getValue();
  AUTOJIT_DEBUG(dbgs() << "autojitd: Materialized at address 0x"
                       << format("%016" PRIx64, FuncAddr) << "\n");

  // Serialize the result
  size_t ResultSize = SPSRetList::size(FuncAddr);
  auto Result = shared::WrapperFunctionResult::allocate(ResultSize);
  shared::SPSOutputBuffer OB(Result.data(), Result.size());

  if (!SPSRetList::serialize(OB, FuncAddr)) {
    return shared::WrapperFunctionResult::createOutOfBandError("Failed to serialize result")
        .release();
  }

  return Result.release();
}

} // extern "C"

/* ============================================================================
 * Main daemon entry point
 * ============================================================================ */

int main(int argc, char *argv[]) {
  // Check debug flag
  if (const char *Var = std::getenv("AUTOJIT_DEBUG")) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes") {
      g_autojit_debug = true;
    }
  }

  AUTOJIT_DEBUG(dbgs() << "autojitd: Starting daemon\n");

  ExitOnError ExitOnErr("autojitd: ");

  // Create SimpleRemoteEPC server that communicates over stdin/stdout
  // This handles the executor-side protocol - the stub will send memory allocation,
  // symbol lookup, and other executor requests to this server
  g_epc_server = ExitOnErr(
      SimpleRemoteEPCServer::Create<FDSimpleRemoteEPCTransport>(
          [](SimpleRemoteEPCServer::Setup &S) -> Error {
            // Register our RPC wrapper functions that the stub can call
            S.bootstrapSymbols()["autojit_rpc_register"] =
                ExecutorAddr::fromPtr(autojit_rpc_register);
            S.bootstrapSymbols()["autojit_rpc_materialize"] =
                ExecutorAddr::fromPtr(autojit_rpc_materialize);

            return Error::success();
          },
          STDIN_FILENO,   // Read from stdin
          STDOUT_FILENO   // Write to stdout
      ));

  AUTOJIT_DEBUG(dbgs() << "autojitd: EPC server created, entering event loop\n");

  // Run the server until the host disconnects
  ExitOnErr(g_epc_server->waitForDisconnect());

  AUTOJIT_DEBUG(dbgs() << "autojitd: Host disconnected, shutting down\n");

  return 0;
}
