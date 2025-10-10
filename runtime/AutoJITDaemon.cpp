#include "AutoJITCommon.h"
#include "AutoJITConfig.h"

#include "llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h"
#include "llvm/ExecutionEngine/Orc/TargetProcess/SimpleRemoteEPCServer.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace llvm;
using namespace llvm::orc;

extern "C" shared::CWrapperFunctionResult
autojit_rpc_register(const char *ArgData, size_t ArgSize) {
  using SPSArgList = shared::SPSArgList<shared::SPSString>;

  std::string FilePath;
  shared::SPSInputBuffer IB(ArgData, ArgSize);

  if (!SPSArgList::deserialize(IB, FilePath)) {
    return shared::WrapperFunctionResult::createOutOfBandError(
               "Failed to deserialize arguments")
        .release();
  }

  DBG() << "RPC register module: " << FilePath << "\n";
  autojit::submitModule(FilePath.c_str());

  return shared::WrapperFunctionResult().release();
}

extern "C" shared::CWrapperFunctionResult
autojit_rpc_materialize(const char *ArgData, size_t ArgSize) {
  using SPSArgList = shared::SPSArgList<uint64_t>;
  using SPSRetList = shared::SPSArgList<uint64_t>;

  uint64_t Guid;
  shared::SPSInputBuffer IB(ArgData, ArgSize);

  if (!SPSArgList::deserialize(IB, Guid)) {
    return shared::WrapperFunctionResult::createOutOfBandError(
               "Failed to deserialize arguments")
        .release();
  }

  std::string Name = autojit::guidToFnName(Guid);
  DBG() << "Looking up function: " << Name << "\n";

  // TODO: Provide a JIT that is configured for remote EPC
  autojit::AutoJIT &JIT = autojit::AutoJIT::get();

  uint64_t Addr = JIT.lookup(Name.c_str());
  DBG() << "Materialized at address 0x" << format("%016" PRIx64, Addr) << "\n";

  // Serialize the result
  size_t ResultSize = SPSRetList::size(Addr);
  auto Result = shared::WrapperFunctionResult::allocate(ResultSize);
  shared::SPSOutputBuffer OB(Result.data(), Result.size());

  if (!SPSRetList::serialize(OB, Addr)) {
    return shared::WrapperFunctionResult::createOutOfBandError(
               "Failed to serialize result")
        .release();
  }

  return Result.release();
}

// Right now the daemon is always forked as a child process
int main(int argc, char *argv[]) {
  autojit::initializeDebugLog();
  DBG() << "Starting daemon\n";

  // FIXME: We cannot use SimpleRemoteEPCServer here, because it implements the
  // target-process side. We need somehting like that for the JIT side.
  ExitOnError ExitOnErr("autojitd: ");
  auto Server =
      ExitOnErr(SimpleRemoteEPCServer::Create<FDSimpleRemoteEPCTransport>(
          [](SimpleRemoteEPCServer::Setup &S) -> Error {
            // Register RPC wrapper functions that the stub can call
            S.bootstrapSymbols()["autojit_rpc_register"] =
                ExecutorAddr::fromPtr(autojit_rpc_register);
            S.bootstrapSymbols()["autojit_rpc_materialize"] =
                ExecutorAddr::fromPtr(autojit_rpc_materialize);
            S.setDispatcher(
                std::make_unique<SimpleRemoteEPCServer::ThreadDispatcher>());
            return Error::success();
          },
          STDIN_FILENO, // Read from stdin
          STDOUT_FILENO // Write to stdout
          ));

  DBG() << "Daemon entering event loop\n";
  ExitOnErr(Server->waitForDisconnect());

  DBG() << "Host disconnected, daemon shutting down\n";
  return 0;
}
