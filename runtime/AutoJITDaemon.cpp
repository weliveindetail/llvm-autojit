#include "AutoJITRuntime.h"
#include "AutoJITConfig.h"

#include "llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h"
#include "llvm/ExecutionEngine/Orc/TargetProcess/SimpleRemoteEPCServer.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
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
 * RPC Interface Implementation
 * ============================================================================
 *
 * The daemon exposes two RPC functions to the host stub:
 * - autojit_rpc_register(string path) -> void
 * - autojit_rpc_materialize(uint64_t guid) -> uint64_t
 *
 * These are registered as wrapper functions and called via SPS protocol.
 */

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

  // Call the actual runtime registration function
  __llvm_autojit_register(FilePath.c_str());

  // Return void (empty success result)
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

  // Call the actual runtime materialization function
  void *GuidPtr = reinterpret_cast<void *>(Guid);
  __llvm_autojit_materialize(&GuidPtr);
  uint64_t FuncAddr = reinterpret_cast<uint64_t>(GuidPtr);

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
  auto Server = ExitOnErr(
      SimpleRemoteEPCServer::Create<FDSimpleRemoteEPCTransport>(
          [](SimpleRemoteEPCServer::Setup &S) -> Error {
            // Set up dispatcher for handling concurrent requests
#if LLVM_ENABLE_THREADS
            S.setDispatcher(std::make_unique<SimpleRemoteEPCServer::ThreadDispatcher>());
#endif

            // Register our RPC wrapper functions
            S.bootstrapSymbols()["autojit_rpc_register"] =
                ExecutorAddr::fromPtr(autojit_rpc_register);
            S.bootstrapSymbols()["autojit_rpc_materialize"] =
                ExecutorAddr::fromPtr(autojit_rpc_materialize);

            return Error::success();
          },
          STDIN_FILENO,   // Read from stdin
          STDOUT_FILENO   // Write to stdout
      ));

  AUTOJIT_DEBUG(dbgs() << "autojitd: Server created, entering event loop\n");

  // Run the server until the host disconnects
  ExitOnErr(Server->waitForDisconnect());

  AUTOJIT_DEBUG(dbgs() << "autojitd: Host disconnected, shutting down\n");

  return 0;
}
