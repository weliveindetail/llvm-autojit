#include "runtime/remote/Session.h"

#include "runtime/core/OrcCompat.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/DylibManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericMemoryAccess.h>
#include <llvm/ExecutionEngine/Orc/Shared/OrcRTBridge.h>
#include <llvm/ExecutionEngine/Orc/Shared/SimplePackedSerialization.h>
#include <llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Host.h>

#if AUTOJIT_ORC_V24
#include <llvm/ExecutionEngine/Orc/EPCGenericDylibManagerSPS.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManagerSPS.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericMemoryAccessSPS.h>
#include <llvm/ExecutionEngine/Orc/LookupAndApply.h>
#include <llvm/ExecutionEngine/Orc/RecordProxy.h>
#endif

#include <llvm/ExecutionEngine/Orc/MemoryAccess.h>
using MemoryAccess = llvm::orc::MemoryAccess;

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace llvm;
using namespace llvm::orc;

static ExitOnError ExitOnErr("[autojitd] ");

// Result messages carry the result kind in TagAddr, like LLVM 24. The payload
// of an out-of-band error is its message.
static constexpr ExecutorAddr ResultKindValue(0);
static constexpr ExecutorAddr ResultKindOutOfBandError(1);

namespace autojit {

struct RemoteEPCExecutorInfo {
  std::string TargetTriple;
  uint64_t PageSize;
  StringMap<std::vector<char>> BootstrapMap;
  StringMap<ExecutorAddr> BootstrapSymbols;

  MSVCPError deserialize(autojit::WFBuffer Bytes);
};

} // namespace autojit

using SPSRemoteEPCExecutorInfo = shared::SPSTuple<
    shared::SPSString, uint64_t,
    shared::SPSSequence<
        shared::SPSTuple<shared::SPSString, shared::SPSSequence<char>>>,
    shared::SPSSequence<
        shared::SPSTuple<shared::SPSString, shared::SPSExecutorAddr>>>;

template <>
class shared::SPSSerializationTraits<SPSRemoteEPCExecutorInfo,
                                     autojit::RemoteEPCExecutorInfo> {
public:
  static size_t size(const autojit::RemoteEPCExecutorInfo &SI) {
    return SPSRemoteEPCExecutorInfo::AsArgList::size(
        SI.TargetTriple, SI.PageSize, SI.BootstrapMap, SI.BootstrapSymbols);
  }

  static bool deserialize(SPSInputBuffer &IB,
                          autojit::RemoteEPCExecutorInfo &SI) {
    return SPSRemoteEPCExecutorInfo::AsArgList::deserialize(
        IB, SI.TargetTriple, SI.PageSize, SI.BootstrapMap, SI.BootstrapSymbols);
  }
};

namespace autojit {

class Transport : public SimpleRemoteEPCTransport {
public:
  Transport(SimpleRemoteEPCTransportClient &C, int InFD, int OutFD);
  ~Transport() override;

  Error start() override;

  Error sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                    ExecutorAddr TagAddr, ArrayRef<char> ArgBytes) override;

  void disconnect() override;

private:
  Error readBytes(char *Dst, size_t Size, bool *IsEOF = nullptr);
  int writeBytes(const char *Src, size_t Size);
  void listenLoop();

  std::mutex M;
  SimpleRemoteEPCTransportClient &C;
  std::thread ListenerThread;
  int InFD, OutFD;
  std::atomic<bool> Disconnected{false};
  std::atomic<bool> LoopFinished{false};
};

#if !AUTOJIT_ORC_V24
// The stub's dylib manager has LLVM 24's interface
class LegacyDylibManager : public DylibManager {
public:
  static Expected<std::unique_ptr<LegacyDylibManager>>
  Create(ExecutorProcessControl &EPC);

  Expected<tpctypes::DylibHandle> loadDylib(const char *DylibPath) override;
  void lookupSymbolsAsync(ArrayRef<LookupRequest> Request,
                          SymbolLookupCompleteFn Complete) override;

private:
  LegacyDylibManager(ExecutorProcessControl &EPC) : EPC(EPC) {}

  void lookupNext(ArrayRef<LookupRequest> Request,
                  std::vector<tpctypes::LookupResult> Result,
                  SymbolLookupCompleteFn Complete);

  ExecutorProcessControl &EPC;
  ExecutorAddr Instance;
  ExecutorAddr Load;
  ExecutorAddr Lookup;
};
#endif

#if AUTOJIT_ORC_V24
using ArgBytesVector = WFBuffer;
#else
using ArgBytesVector = SimpleRemoteEPCArgBytesVector;
#endif

class RemoteEPC : public ExecutorProcessControl,
                  public SimpleRemoteEPCTransportClient {
public:
  RemoteEPC(std::shared_ptr<SymbolStringPool> SSP,
            std::unique_ptr<TaskDispatcher> D)
      : ExecutorProcessControl(std::move(SSP), std::move(D)) {}

  RemoteEPC(const RemoteEPC &) = delete;
  RemoteEPC &operator=(const RemoteEPC &) = delete;
  RemoteEPC(RemoteEPC &&) = delete;
  RemoteEPC &operator=(RemoteEPC &&) = delete;
  ~RemoteEPC();

  Expected<int32_t> runAsMain(ExecutorAddr, ArrayRef<std::string>) override {
    llvm_unreachable("Daemon is passive");
  }

#if !AUTOJIT_ORC_V24
  Expected<int32_t> runAsVoidFunction(ExecutorAddr) override {
    llvm_unreachable("Daemon is passive");
  }

  Expected<int32_t> runAsIntFunction(ExecutorAddr, int) override {
    llvm_unreachable("Daemon is passive");
  }
#endif

  void handleDisconnect(Error Err) override {
    llvm_unreachable("Daemon is passive");
  }

  int waitForDisconnect();

  Error disconnect() override {
    T->disconnect();
    Disconnecting = true;
    return Error::success();
  }

  bool isQuickHangup() {
    return Disconnecting && !FullShutdownRequested;
  }

  void callWrapperAsync(ExecutorAddr WrapperFnAddr,
                        IncomingWFRHandler OnComplete,
                        ArrayRef<char> ArgBuffer) override;

  Expected<HandleMessageAction>
  handleMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo, ExecutorAddr TagAddr,
                ArgBytesVector ArgBytes) override;

  void setTransport(SimpleRemoteEPCTransport &T) { this->T = &T; }

  Error waitForSetup();
  Error sendSetupMessage(StringMap<ExecutorAddr> Symbols);

#if AUTOJIT_ORC_V24
  Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager() override;
  Expected<std::unique_ptr<DylibManager>> createDefaultDylibMgr() override;
  Expected<std::unique_ptr<MemoryAccess>> createDefaultMemoryAccess() override;
#else
  static Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager(RemoteEPC &SREPC);
  static Expected<std::unique_ptr<MemoryAccess>>
  createDefaultMemoryAccess(RemoteEPC &SREPC);
#endif

  Error sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                    ExecutorAddr TagAddr, ArrayRef<char> ArgBytes);

private:
  Error handleSetup(uint64_t SeqNo, ExecutorAddr TagAddr,
                    ArgBytesVector ArgBytes);
  HandleMessageAction handleHangup(ArgBytesVector ArgBytes);

  Error handleResult(uint64_t SeqNo, ExecutorAddr TagAddr,
                     ArgBytesVector ArgBytes);
  void handleCallWrapper(uint64_t RemoteSeqNo, ExecutorAddr TagAddr,
                         ArgBytesVector ArgBytes);

  uint64_t getNextSeqNo() { return NextSeqNo++; }
  void releaseSeqNo(uint64_t SeqNo) {}

  using PendingCallWrapperResultsMap = DenseMap<uint64_t, IncomingWFRHandler>;

  std::mutex ServerStateMutex;
  std::condition_variable DisconnectCV;
  Error DisconnectErr = Error::success();
  bool Disconnecting = false;
  bool FullShutdownRequested = false;

  SimpleRemoteEPCTransport *T;
#if !AUTOJIT_ORC_V24
  std::unique_ptr<DylibManager> OwnedDylibMgr;
  std::unique_ptr<jitlink::JITLinkMemoryManager> OwnedMemMgr;
  std::unique_ptr<MemoryAccess> OwnedMemAccess;
#endif

  // Each side numbers the calls it makes. Results carry the number of their
  // call. 0 is the Setup message.
  std::atomic<uint64_t> NextSeqNo = 1;
  PendingCallWrapperResultsMap PendingCallWrapperResults;
};

} // namespace autojit

//////////////////////////////////////////////////////////////////// Session ///

autojit::Session::Session(int InFD, int OutFD,
                          std::unique_ptr<ExecutionSession> &ES) {
  // The stub calls concurrently from many threads. Handlers block while they
  // wait for nested calls to the stub, so we don't limit the threads.
  auto D = std::make_unique<DynamicThreadPoolTaskDispatcher>(std::nullopt);
  auto SSP = std::make_shared<SymbolStringPool>();
  ES = std::make_unique<ExecutionSession>(
      std::make_unique<RemoteEPC>(std::move(SSP), std::move(D)));
  EPC_ = static_cast<RemoteEPC *>(&ES->getExecutorProcessControl());
  Transport_ = std::make_unique<Transport>(*EPC_, InFD, OutFD);
  EPC_->setTransport(*Transport_);
}

autojit::Session::~Session() {}

autojit::AutoJIT *autojit::Session::launch(std::unique_ptr<ExecutionSession> ES,
                                           StringMap<ExecutorAddr> Symbols) {
  // Start message queue and wait for setup from target process
  ExitOnErr(EPC_->waitForSetup());

  LLJITBuilder Builder;
  Builder.setExecutionSession(std::move(ES));
  ExitOnErr(AutoJIT_.initialize(Builder));

  // Send our own setup message to the target process
  ExitOnErr(EPC_->sendSetupMessage(std::move(Symbols)));
  return &AutoJIT_;
}

int autojit::Session::waitForDisconnect() { return EPC_->waitForDisconnect(); }

////////////////////////////////////////////////////////////////// Transport ///

struct FDMsgHeader {
  static constexpr unsigned MsgSizeOffset = 0;
  static constexpr unsigned OpCOffset = MsgSizeOffset + sizeof(uint64_t);
  static constexpr unsigned SeqNoOffset = OpCOffset + sizeof(uint64_t);
  static constexpr unsigned TagAddrOffset = SeqNoOffset + sizeof(uint64_t);
  static constexpr unsigned Size = TagAddrOffset + sizeof(uint64_t);
};

autojit::Transport::Transport(SimpleRemoteEPCTransportClient &C, int InFD,
                              int OutFD)
    : C(C), InFD(InFD), OutFD(OutFD) {}

autojit::Transport::~Transport() {
  disconnect();
  ListenerThread.join();
}

Error autojit::Transport::start() {
  ListenerThread = std::thread([this]() { listenLoop(); });
  return Error::success();
}

Error autojit::Transport::sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                                      ExecutorAddr TagAddr,
                                      ArrayRef<char> ArgBytes) {
  char HeaderBuffer[FDMsgHeader::Size];

  *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::MsgSizeOffset)) =
      FDMsgHeader::Size + ArgBytes.size();
  *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::OpCOffset)) =
      static_cast<uint64_t>(OpC);
  *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::SeqNoOffset)) = SeqNo;
  *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::TagAddrOffset)) =
      TagAddr.getValue();

  std::lock_guard<std::mutex> Lock(M);
  if (Disconnected)
    return make_error<StringError>("FD-transport disconnected",
                                   inconvertibleErrorCode());
  if (int ErrNo = writeBytes(HeaderBuffer, FDMsgHeader::Size))
    return errorCodeToError(std::error_code(ErrNo, std::generic_category()));
  if (int ErrNo = writeBytes(ArgBytes.data(), ArgBytes.size()))
    return errorCodeToError(std::error_code(ErrNo, std::generic_category()));
  return Error::success();
}

void autojit::Transport::disconnect() {
  if (Disconnected)
    return; // Return if already disconnected.

  if (Error Err =
          sendMessage(SimpleRemoteEPCOpcode::Hangup, 0, ExecutorAddr{}, {})) {
    LOG() << "Failed to sent final Hangup\n";
  }

  Disconnected = true;
  bool CloseOutFD = InFD != OutFD;

  shutdown(InFD, SHUT_RD);
  if (CloseOutFD)
    shutdown(InFD, SHUT_RD);

  while (!LoopFinished) ;

  while (close(InFD) == -1)
    if (errno == EBADF)
      break;

  if (CloseOutFD)
    while (close(OutFD) == -1)
      if (errno == EBADF)
        break;
}

Error autojit::Transport::readBytes(char *Dst, size_t Size, bool *IsEOF) {
  assert((Size == 0 || Dst) && "Attempt to read into null.");
  ssize_t Completed = 0;
  while (Completed < static_cast<ssize_t>(Size)) {
    ssize_t Read = ::read(InFD, Dst + Completed, Size - Completed);
    if (Read <= 0) {
      auto ErrNo = errno;
      if (Read == 0) {
        if (Completed == 0 && IsEOF) {
          *IsEOF = true;
          return Error::success();
        }
        return make_error<StringError>("Unexpected end-of-file",
                                       inconvertibleErrorCode());
      }
      if (ErrNo == EAGAIN || ErrNo == EINTR)
        continue;
      std::lock_guard<std::mutex> Lock(M);
      if (Disconnected && IsEOF) { // disconnect called,  pretend this is EOF.
        *IsEOF = true;
        return Error::success();
      }
      return errorCodeToError(std::error_code(ErrNo, std::generic_category()));
    }
    Completed += Read;
  }
  return Error::success();
}

int autojit::Transport::writeBytes(const char *Src, size_t Size) {
  assert((Size == 0 || Src) && "Attempt to append from null.");
  ssize_t Completed = 0;
  while (Completed < static_cast<ssize_t>(Size)) {
    ssize_t Written = ::write(OutFD, Src + Completed, Size - Completed);
    if (Written < 0) {
      auto ErrNo = errno;
      if (ErrNo == EAGAIN || ErrNo == EINTR)
        continue;
      return ErrNo;
    }
    Completed += Written;
  }
  return 0;
}

void autojit::Transport::listenLoop() {
  while (!Disconnected) {
    // Read the header buffer
    char HeaderBuffer[FDMsgHeader::Size];
    {
      bool IsEOF = false;
      if (auto Err = readBytes(HeaderBuffer, FDMsgHeader::Size, &IsEOF)) {
        LOG() << "Failed to read message header: " << toString(std::move(Err))
              << "\n";
        continue;
      }
      if (IsEOF) {
        if (!Disconnected) {
          LOG() << "Unexpected disconnect\n";
        }
        break;
      }
    }

    // Decode header buffer
    uint64_t MsgSize;
    SimpleRemoteEPCOpcode OpC;
    uint64_t SeqNo;
    ExecutorAddr TagAddr;

    MsgSize =
        *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::MsgSizeOffset));
    OpC = static_cast<SimpleRemoteEPCOpcode>(static_cast<uint64_t>(
        *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::OpCOffset))));
    SeqNo =
        *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::SeqNoOffset));
    TagAddr.setValue(
        *((support::ulittle64_t *)(HeaderBuffer + FDMsgHeader::TagAddrOffset)));

    if (MsgSize < FDMsgHeader::Size) {
      LOG() << "Message size too small: " << MsgSize << " bytes\n";
      continue;
    }

    // Read the argument bytes
#if AUTOJIT_ORC_V24
    auto ArgBytes = WFBuffer::allocate(MsgSize - FDMsgHeader::Size);
#else
    ArgBytesVector ArgBytes;
    ArgBytes.resize(MsgSize - FDMsgHeader::Size);
#endif
    if (auto Err = readBytes(ArgBytes.data(), ArgBytes.size())) {
      LOG() << "Failed to read message payload: " << toString(std::move(Err))
            << "\n";
      continue;
    }

    auto Status = C.handleMessage(OpC, SeqNo, TagAddr, std::move(ArgBytes));
    if (!Status) {
      LOG() << "Failed to handle message: " << toString(Status.takeError())
            << "\n";
      continue;
    }

    if (*Status == SimpleRemoteEPCTransportClient::EndSession)
      break;
  }

  assert(Disconnected || static_cast<RemoteEPC *>(&C)->isQuickHangup());
  LoopFinished = true;
}

////////////////////////////////////////////////////////////////// RemoteEPC ///

autojit::RemoteEPC::~RemoteEPC() {
#if !defined(NDEBUG)
  std::lock_guard<std::mutex> Lock(ServerStateMutex);
  assert(Disconnecting && "Destroyed without disconnection");

  // Still unchecked if we never reached waitForDisconnect()
  consumeError(std::move(DisconnectErr));
#endif
}

#if !AUTOJIT_ORC_V24
Expected<std::unique_ptr<autojit::LegacyDylibManager>>
autojit::LegacyDylibManager::Create(ExecutorProcessControl &EPC) {
  std::unique_ptr<LegacyDylibManager> M(new LegacyDylibManager(EPC));
  if (auto Err = EPC.getBootstrapSymbols(
          {{M->Instance, "orc_rt_ci_NativeDylibManager_Instance"},
           {M->Load, "orc_rt_ci_sps_NativeDylibManager_load"},
           {M->Lookup, "orc_rt_ci_sps_NativeDylibManager_lookup"}}))
    return std::move(Err);
  return std::move(M);
}

Expected<tpctypes::DylibHandle>
autojit::LegacyDylibManager::loadDylib(const char *DylibPath) {
  using namespace shared;
  using SPSSig =
      SPSExpected<SPSExecutorAddr>(SPSExecutorAddr, SPSString, uint64_t);
  Expected<ExecutorAddr> Handle((ExecutorAddr()));
  if (auto Err = EPC.callSPSWrapper<SPSSig>(Load, Handle, Instance,
                                            StringRef(DylibPath), uint64_t(0)))
    return std::move(Err);
  return Handle;
}

void autojit::LegacyDylibManager::lookupSymbolsAsync(
    ArrayRef<LookupRequest> Request, SymbolLookupCompleteFn Complete) {
  lookupNext(Request, {}, std::move(Complete));
}

// Look up one request after the other
void autojit::LegacyDylibManager::lookupNext(
    ArrayRef<LookupRequest> Request, std::vector<tpctypes::LookupResult> Result,
    SymbolLookupCompleteFn Complete) {
  if (Request.empty())
    return Complete(std::move(Result));

  RemoteSymbolLookupSet Symbols;
  for (const auto &[Name, Flags] : Request.front().Symbols)
    Symbols.push_back({(*Name).str(), Flags == SymbolLookupFlags::RequiredSymbol});

  using namespace shared;
  using SPSSig = SPSExpected<SPSSequence<SPSOptional<SPSExecutorAddr>>>(
      SPSExecutorAddr, SPSExecutorAddr, SPSRemoteSymbolLookupSet);
  EPC.callSPSWrapperAsync<SPSSig>(
      Lookup,
      [this, Request, Result = std::move(Result),
       Complete = std::move(Complete)](
          Error SerializationErr,
          Expected<std::vector<std::optional<ExecutorAddr>>> Addrs) mutable {
        if (SerializationErr) {
          cantFail(Addrs.takeError());
          return Complete(std::move(SerializationErr));
        }
        if (!Addrs)
          return Complete(Addrs.takeError());
        // LLVM 21 uses null addresses for missing symbols
        Result.push_back({});
        for (const auto &Addr : *Addrs)
          Result.back().push_back(
              Addr ? ExecutorSymbolDef(*Addr, JITSymbolFlags::Exported)
                   : ExecutorSymbolDef());
        lookupNext(Request.drop_front(), std::move(Result),
                   std::move(Complete));
      },
      Instance, Request.front().Handle, Symbols);
}
#endif

void autojit::RemoteEPC::callWrapperAsync(ExecutorAddr WrapperFnAddr,
                                          IncomingWFRHandler OnComplete,
                                          ArrayRef<char> ArgBuffer) {
  {
    std::unique_lock<std::mutex> Lock(ServerStateMutex);
    if (isQuickHangup()) {
      LOG() << "Warning: ignore RPC invocation after disconnect\n";
      // A zero byte decodes as both, void and ErrorSuccess
      auto Result = autojit::WFBuffer::allocate(1);
      Result.data()[0] = '\0';
      OnComplete(std::move(Result));
      return;
    }
  }

  // The caller waits for a result, so we can't just drop the call
  if (!WrapperFnAddr) {
    OnComplete(autojit::WFBuffer::createOutOfBandError(
        "Call to null wrapper function in the executor"));
    return;
  }

  uint64_t SeqNo;
  {
    std::lock_guard<std::mutex> Lock(ServerStateMutex);
    SeqNo = getNextSeqNo();
    assert(!PendingCallWrapperResults.count(SeqNo) && "SeqNo already in use");
    PendingCallWrapperResults[SeqNo] = std::move(OnComplete);
  }

  if (auto Err = sendMessage(SimpleRemoteEPCOpcode::CallWrapper, SeqNo,
                             WrapperFnAddr, ArgBuffer)) {
    IncomingWFRHandler H;

    // We just registered OnComplete, but there may be a race between this
    // thread returning from sendMessage and handleDisconnect being called from
    // the transport's listener thread. If handleDisconnect gets there first
    // then it will have failed 'H' for us. If we get there first (or if
    // handleDisconnect already ran) then we need to take care of it.
    {
      std::lock_guard<std::mutex> Lock(ServerStateMutex);
      auto I = PendingCallWrapperResults.find(SeqNo);
      if (I != PendingCallWrapperResults.end()) {
        H = std::move(I->second);
        PendingCallWrapperResults.erase(I);
      }
    }

    if (H)
      H(autojit::WFBuffer::createOutOfBandError("disconnecting"));

    getExecutionSession().reportError(std::move(Err));
  }
}

Expected<SimpleRemoteEPCTransportClient::HandleMessageAction>
autojit::RemoteEPC::handleMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                                  ExecutorAddr TagAddr,
                                  ArgBytesVector ArgBytes) {

  {
    DBG() << "RemoteEPC::handleMessage: opc = ";
    switch (OpC) {
    case SimpleRemoteEPCOpcode::Setup:
      DBG() << "Setup";
      assert(SeqNo == 0 && "Non-zero SeqNo for Setup?");
      assert(!TagAddr && "Non-zero TagAddr for Setup?");
      break;
    case SimpleRemoteEPCOpcode::Hangup:
      DBG() << "Hangup";
      assert(SeqNo == 0 && "Non-zero SeqNo for Hangup?");
      assert(!TagAddr && "Non-zero TagAddr for Hangup?");
      break;
    case SimpleRemoteEPCOpcode::Result:
      DBG() << "Result";
      assert((TagAddr == ResultKindValue ||
              TagAddr == ResultKindOutOfBandError) &&
             "Unknown result kind");
      break;
    case SimpleRemoteEPCOpcode::CallWrapper:
      DBG() << "CallWrapper";
      break;
    }
    DBG() << ", seqno = " << SeqNo << ", tag-addr = " << TagAddr
           << ", arg-buffer = " << formatv("{0:x}", ArgBytes.size())
           << " bytes\n";
  }

  using UT = std::underlying_type_t<SimpleRemoteEPCOpcode>;
  if (static_cast<UT>(OpC) > static_cast<UT>(SimpleRemoteEPCOpcode::LastOpC))
    return make_error<StringError>("Unexpected opcode",
                                   inconvertibleErrorCode());

  switch (OpC) {
  case SimpleRemoteEPCOpcode::Setup:
    if (auto Err = handleSetup(SeqNo, TagAddr, std::move(ArgBytes)))
      return std::move(Err);
    break;
  case SimpleRemoteEPCOpcode::Result:
    if (auto Err = handleResult(SeqNo, TagAddr, std::move(ArgBytes)))
      return std::move(Err);
    break;
  case SimpleRemoteEPCOpcode::CallWrapper:
    if (TagAddr.getValue() == 0) {
      LOG() << "Warning: supressing invocation of nullptr in daemon process!\n";
      break;
    }
    handleCallWrapper(SeqNo, TagAddr, std::move(ArgBytes));
    break;
  case SimpleRemoteEPCOpcode::Hangup:
    return handleHangup(std::move(ArgBytes));
  }
  return ContinueSession;
}

SimpleRemoteEPCTransportClient::HandleMessageAction
autojit::RemoteEPC::handleHangup(ArgBytesVector ArgBytes) {
  auto WFR =
      autojit::WFBuffer::copyFrom(ArgBytes.data(), ArgBytes.size());
  if (const char *ErrMsg = WFR.getOutOfBandError()) {
    LOG() << "Hangup error: " << ErrMsg << "\n";
    return EndSession;
  }

  using SPSSerialize = shared::SPSArgList<bool>;
  shared::SPSInputBuffer IB(WFR.data(), WFR.size());
  if (!SPSSerialize::deserialize(IB, FullShutdownRequested)) {
    DBG() << "Hangup-decode error\n";
  }

  std::unique_lock<std::mutex> Lock(ServerStateMutex);
  Disconnecting = true;
  DisconnectCV.notify_all();

  if (!FullShutdownRequested)
    return EndSession;

  return ContinueSession;
}

int autojit::RemoteEPC::waitForDisconnect() {
  std::unique_lock<std::mutex> Lock(ServerStateMutex);
  DisconnectCV.wait(Lock, [this]() { return Disconnecting; });
  if (DisconnectErr) {
    DBG() << "Disconnect-decode error: " << toString(std::move(DisconnectErr))
          << "\n";
    return 1; // TODO: convert to error-code?
  }
  return 0;
}

#if AUTOJIT_ORC_V24
Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
autojit::RemoteEPC::createDefaultMemoryManager() {
  return sps::createEPCGenericJITLinkMemoryManager(getExecutionSession());
}

Expected<std::unique_ptr<DylibManager>>
autojit::RemoteEPC::createDefaultDylibMgr() {
  return sps::createEPCGenericDylibManager(getExecutionSession());
}

// The stub doesn't implement reads
Expected<std::unique_ptr<MemoryAccess>>
autojit::RemoteEPC::createDefaultMemoryAccess() {
  using namespace sps;
  EPCGenericMemoryAccess::Funcs F;
  if (auto Err = lookupAndApply(
          getExecutionSession().getBootstrapJITDylib(),
          {recordProxy<MemWriteUInt8sProxySpec>(&F.WriteUInt8s),
           recordProxy<MemWriteUInt16sProxySpec>(&F.WriteUInt16s),
           recordProxy<MemWriteUInt32sProxySpec>(&F.WriteUInt32s),
           recordProxy<MemWriteUInt64sProxySpec>(&F.WriteUInt64s),
           recordProxy<MemWritePointersProxySpec>(&F.WritePointers),
           recordProxy<MemWriteBuffersProxySpec>(&F.WriteBuffers)}))
    return std::move(Err);
  return std::make_unique<EPCGenericMemoryAccess>(getExecutionSession(),
                                                  std::move(F));
}
#else
Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
autojit::RemoteEPC::createDefaultMemoryManager(RemoteEPC &SREPC) {
  EPCGenericJITLinkMemoryManager::SymbolAddrs SAs;
  if (auto Err = SREPC.getBootstrapSymbols(
          {{SAs.Allocator, "orc_rt_ci_SimpleNativeMemoryMap_Instance"},
           {SAs.Reserve, "orc_rt_ci_sps_SimpleNativeMemoryMap_reserve"},
           // The stub keeps the old finalize for us, LLVM 24 initializes
           {SAs.Finalize, rt::SimpleExecutorMemoryManagerFinalizeWrapperName},
           // Release runs the dealloc actions, like deallocate
           {SAs.Deallocate,
            "orc_rt_ci_sps_SimpleNativeMemoryMap_releaseMultiple"}}))
    return std::move(Err);

  return std::make_unique<EPCGenericJITLinkMemoryManager>(SREPC, SAs);
}

Expected<std::unique_ptr<MemoryAccess>>
autojit::RemoteEPC::createDefaultMemoryAccess(RemoteEPC &SREPC) {
  EPCGenericMemoryAccess::FuncAddrs FAs;
  if (auto Err = SREPC.getBootstrapSymbols(
          {{FAs.WriteUInt8s, "orc_rt_ci_sps_mem_write_uint8s"},
           {FAs.WriteUInt16s, "orc_rt_ci_sps_mem_write_uint16s"},
           {FAs.WriteUInt32s, "orc_rt_ci_sps_mem_write_uint32s"},
           {FAs.WriteUInt64s, "orc_rt_ci_sps_mem_write_uint64s"},
           {FAs.WriteBuffers, "orc_rt_ci_sps_mem_write_buffers"},
           {FAs.WritePointers, "orc_rt_ci_sps_mem_write_pointers"}}))
    return std::move(Err);

  return std::make_unique<EPCGenericMemoryAccess>(SREPC, FAs);
}
#endif

Error autojit::RemoteEPC::sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                                      ExecutorAddr TagAddr,
                                      ArrayRef<char> ArgBytes) {
  {
    DBG() << "RemoteEPC::sendMessage: opc = ";
    switch (OpC) {
    case SimpleRemoteEPCOpcode::Setup:
      DBG() << "Setup";
      assert(!TagAddr && "Non-zero TagAddr for Setup?");
      break;
    case SimpleRemoteEPCOpcode::Hangup:
      DBG() << "Hangup";
      assert(SeqNo == 0 && "Non-zero SeqNo for Hangup?");
      assert(!TagAddr && "Non-zero TagAddr for Hangup?");
      break;
    case SimpleRemoteEPCOpcode::Result:
      DBG() << "Result";
      assert((TagAddr == ResultKindValue ||
              TagAddr == ResultKindOutOfBandError) &&
             "Unknown result kind");
      break;
    case SimpleRemoteEPCOpcode::CallWrapper:
      DBG() << "CallWrapper";
      break;
    }
    DBG() << ", seqno = " << SeqNo << ", tag-addr = " << TagAddr
           << ", arg-buffer = " << formatv("{0:x}", ArgBytes.size())
           << " bytes\n";
  }

  return T->sendMessage(OpC, SeqNo, TagAddr, ArgBytes);
}

Error autojit::RemoteEPC::handleSetup(uint64_t RemoteSeqNo,
                                      ExecutorAddr TagAddr,
                                      ArgBytesVector ArgBytes) {
  if (TagAddr)
    return make_error<StringError>("Setup packet TagAddr not zero",
                                   inconvertibleErrorCode());

  std::lock_guard<std::mutex> Lock(ServerStateMutex);
  auto I = PendingCallWrapperResults.find(0);
  assert(PendingCallWrapperResults.size() == 1 &&
         I != PendingCallWrapperResults.end() &&
         "Setup message handler not connectly set up");
  auto SetupMsgHandler = std::move(I->second);
  PendingCallWrapperResults.erase(I);

  auto WFR =
      autojit::WFBuffer::copyFrom(ArgBytes.data(), ArgBytes.size());
  SetupMsgHandler(std::move(WFR));
  return Error::success();
}

MSVCPError autojit::RemoteEPCExecutorInfo::deserialize(
    autojit::WFBuffer Bytes) {
  if (const char *ErrMsg = Bytes.getOutOfBandError())
    return make_error<StringError>(ErrMsg, inconvertibleErrorCode());

  shared::SPSInputBuffer IB(Bytes.data(), Bytes.size());
  if (!shared::SPSArgList<SPSRemoteEPCExecutorInfo>::deserialize(IB, *this))
    return make_error<StringError>("Could not deserialize setup message",
                                   inconvertibleErrorCode());
  return Error::success();
}

#if !AUTOJIT_ORC_V24
static StringMap<ExecutorAddr> patchSymbolNames(StringMap<ExecutorAddr> Map) {
  auto RenameEntry = [&Map](StringRef From, StringRef To) {
    auto It = Map.find(From);
    if (It != Map.end()) {
      // Inserting may invalidate the iterator
      ExecutorAddr Addr = It->second;
      Map.erase(It);
      Map.try_emplace(To, Addr);
    }
  };

  // LLVM 21 looks up the EH frame alloc actions by these names
  RenameEntry("orc_rt_ci_aa_sps_DWARFEHFrameRegistrar_registerSection",
              rt::RegisterEHFrameSectionAllocActionName);
  RenameEntry("orc_rt_ci_aa_sps_DWARFEHFrameRegistrar_deregisterSection",
              rt::DeregisterEHFrameSectionAllocActionName);

  return Map;
}
#endif

Error autojit::RemoteEPC::waitForSetup() {
  std::promise<MSVCPError> EIP;
  RemoteEPCExecutorInfo EI;
  auto EIF = EIP.get_future();

  // Prepare a handler for the setup packet.
  PendingCallWrapperResults[0] =
      RunInPlace()([&](autojit::WFBuffer SetupMsgBytes) {
        EIP.set_value(EI.deserialize(std::move(SetupMsgBytes)));
      });

  // Start the transport.
  if (auto Err = T->start())
    return Err;

  // Wait for setup packet to arrive.
  if (auto Err = EIF.get()) {
    T->disconnect();
    return Err;
  }

  {
    DBG() << "RemoteEPC received setup message:\n"
           << "  Triple: " << EI.TargetTriple << "\n"
           << "  Page size: " << EI.PageSize << "\n"
           << "  Bootstrap map" << (EI.BootstrapMap.empty() ? " empty" : ":")
           << "\n";
    for (const auto &KV : EI.BootstrapMap)
      DBG() << "    " << KV.first() << ": " << KV.second.size()
             << "-byte SPS encoded buffer\n";
    DBG() << "  Bootstrap symbols"
           << (EI.BootstrapSymbols.empty() ? " empty" : ":") << "\n";
    for (const auto &KV : EI.BootstrapSymbols)
      DBG() << "    " << KV.first() << ": " << KV.second << "\n";
  }

  // Initialize (base class) members
  this->TargetTriple = Triple(EI.TargetTriple);
  this->PageSize = EI.PageSize;
  this->BootstrapMap = std::move(EI.BootstrapMap);
#if AUTOJIT_ORC_V24
  this->BootstrapSymbols = std::move(EI.BootstrapSymbols);

  // The session copied the bootstrap symbols when we created it, before we
  // received them
  SymbolMap Symbols;
  for (const auto &[Name, Addr] : this->BootstrapSymbols)
    Symbols[ES->intern(Name)] = {Addr, JITSymbolFlags::Exported};
  return ES->getBootstrapJITDylib().define(absoluteSymbols(std::move(Symbols)));
#else
  this->BootstrapSymbols = patchSymbolNames(std::move(EI.BootstrapSymbols));

  // Get dispatch symbols for RPC calls back to the stub
  if (auto Err = getBootstrapSymbols(
          {{JDI.JITDispatchContext, "__orc_rt_jit_dispatch_ctx"},
           {JDI.JITDispatchFunction, "__orc_rt_jit_dispatch"}}))
    return Err;

  OwnedDylibMgr = ExitOnErr(LegacyDylibManager::Create(*this));
  this->DylibMgr = OwnedDylibMgr.get();

  OwnedMemMgr = ExitOnErr(createDefaultMemoryManager(*this));
  this->MemMgr = OwnedMemMgr.get();

  OwnedMemAccess = ExitOnErr(createDefaultMemoryAccess(*this));
  this->MemAccess = OwnedMemAccess.get();

  return Error::success();
#endif
}

Error autojit::RemoteEPC::sendSetupMessage(StringMap<ExecutorAddr> Symbols) {
  SimpleRemoteEPCExecutorInfo EI;
  EI.TargetTriple = sys::getProcessTriple();
  EI.PageSize = ExitOnErr(sys::Process::getPageSize());
  EI.BootstrapSymbols = std::move(Symbols);

  using SPSSerialize =
      shared::SPSArgList<shared::SPSSimpleRemoteEPCExecutorInfo>;
  auto SetupPacketBytes =
      autojit::WFBuffer::allocate(SPSSerialize::size(EI));
  shared::SPSOutputBuffer OB(SetupPacketBytes.data(), SetupPacketBytes.size());
  if (!SPSSerialize::serialize(OB, EI)) {
    LOG() << "Could not encode setup packet\n";
    exit(1);
  }

  return sendMessage(SimpleRemoteEPCOpcode::Setup, getNextSeqNo(),
                     ExecutorAddr(),
                     {SetupPacketBytes.data(), SetupPacketBytes.size()});
}

Error autojit::RemoteEPC::handleResult(uint64_t SeqNo, ExecutorAddr TagAddr,
                                       ArgBytesVector ArgBytes) {
  IncomingWFRHandler SendResult;

  if (TagAddr != ResultKindValue && TagAddr != ResultKindOutOfBandError)
    return make_error<StringError>("Unknown result kind " +
                                       Twine(TagAddr.getValue()),
                                   inconvertibleErrorCode());

  {
    std::lock_guard<std::mutex> Lock(ServerStateMutex);
    auto I = PendingCallWrapperResults.find(SeqNo);
    if (I == PendingCallWrapperResults.end())
      return make_error<StringError>("No call for sequence number " +
                                         Twine(SeqNo),
                                     inconvertibleErrorCode());
    SendResult = std::move(I->second);
    PendingCallWrapperResults.erase(I);
    releaseSeqNo(SeqNo);
  }

  if (TagAddr == ResultKindOutOfBandError) {
    std::string Msg(ArgBytes.data(), ArgBytes.size());
    SendResult(autojit::WFBuffer::createOutOfBandError(Msg));
    return Error::success();
  }

  auto WFR =
      autojit::WFBuffer::copyFrom(ArgBytes.data(), ArgBytes.size());
  SendResult(std::move(WFR));
  return Error::success();
}

void autojit::RemoteEPC::handleCallWrapper(
    uint64_t RemoteSeqNo, ExecutorAddr TagAddr,
    ArgBytesVector ArgBytes) {
  assert(ES && "No ExecutionSession attached");
  D->dispatch(makeGenericNamedTask(
      [this, RemoteSeqNo, TagAddr, ArgBytes = std::move(ArgBytes)]() {
        // Call the wrapper function directly
        using WrapperFnTy =
            autojit::CWFBuffer (*)(const char *, size_t);
        auto *Fn = TagAddr.toPtr<WrapperFnTy>();
        autojit::WFBuffer WFR(Fn(ArgBytes.data(), ArgBytes.size()));

        // Check for out-of-band error before calling .data()
        const char *ErrMsg = WFR.getOutOfBandError();
        if (ErrMsg) {
          DBG() << "RPC function returned out-of-band error: " << ErrMsg
                << "\n";
          if (auto Err = sendMessage(SimpleRemoteEPCOpcode::Result, RemoteSeqNo,
                                     ResultKindOutOfBandError,
                                     {ErrMsg, strlen(ErrMsg)}))
            getExecutionSession().reportError(std::move(Err));
        } else {
          if (auto Err = sendMessage(SimpleRemoteEPCOpcode::Result, RemoteSeqNo,
                                     ResultKindValue, {WFR.data(), WFR.size()}))
            getExecutionSession().reportError(std::move(Err));
        }
      },
      "callWrapper task"));
}
