#pragma once

#include "AutoJITConfig.h"

#include "runtime/core/AutoJIT.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ExecutionEngine/Orc/ExecutorProcessControl.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h>
#include <llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/ErrorHandling.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace autojit {

#if AUTOJIT_LLVM_21
using ArgBytesVector = llvm::orc::SimpleRemoteEPCArgBytesVector;
inline ArgBytesVector allocateArgBytes(size_t Size) {
  ArgBytesVector ArgBytes;
  ArgBytes.resize(Size);
  return ArgBytes;
}
#else
using ArgBytesVector = WFBuffer;
inline ArgBytesVector allocateArgBytes(size_t Size) {
  return WFBuffer::allocate(Size);
}
#endif

// The parts of the executor process control that all LLVM versions share
class RemoteEPC : public llvm::orc::ExecutorProcessControl,
                  public llvm::orc::SimpleRemoteEPCTransportClient {
public:
  RemoteEPC(std::shared_ptr<llvm::orc::SymbolStringPool> SSP,
            std::unique_ptr<llvm::orc::TaskDispatcher> D)
      : llvm::orc::ExecutorProcessControl(std::move(SSP), std::move(D)) {}

  RemoteEPC(const RemoteEPC &) = delete;
  RemoteEPC &operator=(const RemoteEPC &) = delete;
  RemoteEPC(RemoteEPC &&) = delete;
  RemoteEPC &operator=(RemoteEPC &&) = delete;
  ~RemoteEPC();

  llvm::Expected<int32_t> runAsMain(llvm::orc::ExecutorAddr,
                                    llvm::ArrayRef<std::string>) override {
    llvm_unreachable("Daemon is passive");
  }

  void handleDisconnect(llvm::Error Err) override {
    llvm_unreachable("Daemon is passive");
  }

  int waitForDisconnect();

  llvm::Error disconnect() override {
    T->disconnect();
    Disconnecting = true;
    return llvm::Error::success();
  }

  bool isQuickHangup() { return Disconnecting && !FullShutdownRequested; }

  void callWrapperAsync(llvm::orc::ExecutorAddr WrapperFnAddr,
                        IncomingWFRHandler OnComplete,
                        llvm::ArrayRef<char> ArgBuffer) override;

  llvm::Expected<HandleMessageAction>
  handleMessage(llvm::orc::SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                llvm::orc::ExecutorAddr TagAddr,
                ArgBytesVector ArgBytes) override;

  void setTransport(llvm::orc::SimpleRemoteEPCTransport &T) { this->T = &T; }

  llvm::Error waitForSetup();
  llvm::Error
  sendSetupMessage(llvm::StringMap<llvm::orc::ExecutorAddr> Symbols);

  llvm::Error sendMessage(llvm::orc::SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                          llvm::orc::ExecutorAddr TagAddr,
                          llvm::ArrayRef<char> ArgBytes);

protected:
  // Completes the setup once we received the bootstrap symbols
  virtual llvm::Error finishSetup() = 0;

private:
  llvm::Error handleSetup(uint64_t SeqNo, llvm::orc::ExecutorAddr TagAddr,
                          ArgBytesVector ArgBytes);
  HandleMessageAction handleHangup(ArgBytesVector ArgBytes);

  llvm::Error handleResult(uint64_t SeqNo, llvm::orc::ExecutorAddr TagAddr,
                           ArgBytesVector ArgBytes);
  void handleCallWrapper(uint64_t RemoteSeqNo, llvm::orc::ExecutorAddr TagAddr,
                         ArgBytesVector ArgBytes);

  uint64_t getNextSeqNo() { return NextSeqNo++; }
  void releaseSeqNo(uint64_t SeqNo) {}

  using PendingCallWrapperResultsMap =
      llvm::DenseMap<uint64_t, IncomingWFRHandler>;

  std::mutex ServerStateMutex;
  std::condition_variable DisconnectCV;
  llvm::Error DisconnectErr = llvm::Error::success();
  bool Disconnecting = false;
  bool FullShutdownRequested = false;

  llvm::orc::SimpleRemoteEPCTransport *T;

  // Each side numbers the calls it makes. Results carry the number of their
  // call. 0 is the Setup message.
  std::atomic<uint64_t> NextSeqNo = 1;
  PendingCallWrapperResultsMap PendingCallWrapperResults;
};

/// Create the executor process control for the LLVM version we build against.
/// DefaultRemoteEPC.cpp and LegacyRemoteEPC.cpp implement it.
std::unique_ptr<RemoteEPC>
createSessionEPC(std::shared_ptr<llvm::orc::SymbolStringPool> SSP,
                 std::unique_ptr<llvm::orc::TaskDispatcher> D);

} // namespace autojit
