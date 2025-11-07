#include "runtime/remote/Session.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericDylibManager.h>
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

#if LLVM_VERSION_MAJOR >= 21
#include <llvm/ExecutionEngine/Orc/MemoryAccess.h>
using MemoryAccess = llvm::orc::MemoryAccess;
#else
using MemoryAccess = llvm::orc::ExecutorProcessControl::MemoryAccess;
#endif

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

namespace autojit {

enum StdLib : uint64_t {
  LibcGnu = 1 << 0,
  LibcMusl = 1 << 1,
  LibStdCxx = 1 << 8,
  LibCxx = 1 << 9,
};

struct RemoteEPCExecutorInfo {
  std::string TargetTriple;
  uint64_t PageSize;
  uint64_t StdLibs;
  StringMap<std::vector<char>> BootstrapMap;
  StringMap<ExecutorAddr> BootstrapSymbols;

  MSVCPError deserialize(shared::WrapperFunctionResult Bytes);
  bool hasSupportedCxxStdlib() const {
    return (StdLibs & (LibCxx | LibStdCxx)) != 0;
  }
};

} // namespace autojit

using SPSRemoteEPCExecutorInfo = shared::SPSTuple<
    shared::SPSString, uint64_t, uint64_t,
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
        SI.TargetTriple, SI.PageSize, SI.StdLibs, SI.BootstrapMap,
        SI.BootstrapSymbols);
  }

  static bool deserialize(SPSInputBuffer &IB,
                          autojit::RemoteEPCExecutorInfo &SI) {
    return SPSRemoteEPCExecutorInfo::AsArgList::deserialize(
        IB, SI.TargetTriple, SI.PageSize, SI.StdLibs, SI.BootstrapMap,
        SI.BootstrapSymbols);
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

class RemoteEPC : public ExecutorProcessControl,
                  public SimpleRemoteEPCTransportClient,
                  private DylibManager {
public:
  RemoteEPC(std::shared_ptr<SymbolStringPool> SSP,
            std::unique_ptr<TaskDispatcher> D)
      : ExecutorProcessControl(std::move(SSP), std::move(D)) {
    // Callback result that can be decoded as void or ErrorSuccess
    DummyResultValue = '\0';
    DummyResult.Data.ValuePtr = &DummyResultValue;
    DummyResult.Size = 1;

    this->DylibMgr = this;
  }

  RemoteEPC(const RemoteEPC &) = delete;
  RemoteEPC &operator=(const RemoteEPC &) = delete;
  RemoteEPC(RemoteEPC &&) = delete;
  RemoteEPC &operator=(RemoteEPC &&) = delete;
  ~RemoteEPC();

  Expected<int32_t> runAsMain(ExecutorAddr, ArrayRef<std::string>) override {
    llvm_unreachable("Daemon is passive");
  }

  Expected<int32_t> runAsVoidFunction(ExecutorAddr) override {
    llvm_unreachable("Daemon is passive");
  }

  Expected<int32_t> runAsIntFunction(ExecutorAddr, int) override {
    llvm_unreachable("Daemon is passive");
  }

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
                SimpleRemoteEPCArgBytesVector ArgBytes) override;

  void setTransport(SimpleRemoteEPCTransport &T) { this->T = &T; }
  bool hasSupportedCxxStdlib() const { return HaveSupportedCxxStdlib; }

  Error waitForSetup();
  Error sendSetupMessage(StringMap<ExecutorAddr> Symbols);

  static Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager(RemoteEPC &SREPC);
  static Expected<std::unique_ptr<MemoryAccess>>
  createDefaultMemoryAccess(RemoteEPC &SREPC);

  Error sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                    ExecutorAddr TagAddr, ArrayRef<char> ArgBytes);

private:
  Error handleSetup(uint64_t SeqNo, ExecutorAddr TagAddr,
                    SimpleRemoteEPCArgBytesVector ArgBytes);
  HandleMessageAction handleHangup(SimpleRemoteEPCArgBytesVector ArgBytes);

  Error handleResult(uint64_t SeqNo, ExecutorAddr TagAddr,
                     SimpleRemoteEPCArgBytesVector ArgBytes);
  void handleCallWrapper(uint64_t RemoteSeqNo, ExecutorAddr TagAddr,
                         SimpleRemoteEPCArgBytesVector ArgBytes);

  uint64_t getNextSeqNo() { return NextSeqNo++; }
  void releaseSeqNo(uint64_t SeqNo) {}
  Error countSeqNo(uint64_t RemoteSeqNo);

  Expected<tpctypes::DylibHandle> loadDylib(const char *DylibPath) override;

  void lookupSymbolsAsync(ArrayRef<LookupRequest> Request,
                          SymbolLookupCompleteFn F) override;

  using PendingCallWrapperResultsMap = DenseMap<uint64_t, IncomingWFRHandler>;

  std::mutex ServerStateMutex;
  std::condition_variable DisconnectCV;
  Error DisconnectErr = Error::success();
  bool Disconnecting = false;
  bool FullShutdownRequested = false;
  shared::CWrapperFunctionResult DummyResult;
  char DummyResultValue;

  SimpleRemoteEPCTransport *T;
  bool HaveSupportedCxxStdlib;
  std::unique_ptr<EPCGenericDylibManager> EPCDylibMgr;
  std::unique_ptr<jitlink::JITLinkMemoryManager> OwnedMemMgr;
  std::unique_ptr<MemoryAccess> OwnedMemAccess;

  std::atomic<uint64_t> NextSeqNo = 0;
  PendingCallWrapperResultsMap PendingCallWrapperResults;
};

} // namespace autojit

//////////////////////////////////////////////////////////////////// Session ///

autojit::Session::Session(int InFD, int OutFD,
                          std::unique_ptr<ExecutionSession> &ES) {
  unsigned NumThreads = 1;
  auto D = std::make_unique<DynamicThreadPoolTaskDispatcher>(NumThreads);
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
  ExitOnErr(AutoJIT_.initialize(Builder, EPC_->hasSupportedCxxStdlib()));

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
    SimpleRemoteEPCArgBytesVector ArgBytes;
    ArgBytes.resize(MsgSize - FDMsgHeader::Size);
    if (auto Err = readBytes(ArgBytes.data(), ArgBytes.size())) {
      LOG() << "Failed to read message payload: " << toString(std::move(Err))
            << "\n";
      continue;
    }

    auto Status = C.handleMessage(OpC, SeqNo, TagAddr, ArgBytes);
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

Expected<tpctypes::DylibHandle>
autojit::RemoteEPC::loadDylib(const char *DylibPath) {
  return EPCDylibMgr->open(DylibPath, 0);
}

/// Async helper to chain together calls to DylibMgr::lookupAsync to fulfill all
/// all the requests.
/// FIXME: The dylib manager should support multiple LookupRequests natively.
static void
lookupSymbolsAsyncHelper(EPCGenericDylibManager &DylibMgr,
                         ArrayRef<DylibManager::LookupRequest> Request,
                         std::vector<tpctypes::LookupResult> Result,
                         DylibManager::SymbolLookupCompleteFn Complete) {
  if (Request.empty())
    return Complete(std::move(Result));

  auto &Element = Request.front();
  DylibMgr.lookupAsync(Element.Handle, Element.Symbols,
                       [&DylibMgr, Request, Complete = std::move(Complete),
                        Result = std::move(Result)](auto R) mutable {
                         if (!R)
                           return Complete(R.takeError());
                         Result.push_back({});
                         Result.back().reserve(R->size());
                         for (auto Addr : *R)
                           Result.back().push_back(Addr);

                         lookupSymbolsAsyncHelper(
                             DylibMgr, Request.drop_front(), std::move(Result),
                             std::move(Complete));
                       });
}

void autojit::RemoteEPC::lookupSymbolsAsync(ArrayRef<LookupRequest> Request,
                                            SymbolLookupCompleteFn Complete) {
  lookupSymbolsAsyncHelper(*EPCDylibMgr, Request, {}, std::move(Complete));
}

void autojit::RemoteEPC::callWrapperAsync(ExecutorAddr WrapperFnAddr,
                                          IncomingWFRHandler OnComplete,
                                          ArrayRef<char> ArgBuffer) {
  {
    std::unique_lock<std::mutex> Lock(ServerStateMutex);
    if (isQuickHangup()) {
      LOG() << "Warning: ignore RPC invocation after disconnect\n";
      OnComplete(DummyResult); // Can be both, void or ErrorSuccess
    }
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
      H(shared::WrapperFunctionResult::createOutOfBandError("disconnecting"));

    getExecutionSession().reportError(std::move(Err));
  }
}

Expected<SimpleRemoteEPCTransportClient::HandleMessageAction>
autojit::RemoteEPC::handleMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                                  ExecutorAddr TagAddr,
                                  SimpleRemoteEPCArgBytesVector ArgBytes) {

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
      assert(!TagAddr && "Non-zero TagAddr for Result?");
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
autojit::RemoteEPC::handleHangup(SimpleRemoteEPCArgBytesVector ArgBytes) {
  auto WFR =
      shared::WrapperFunctionResult::copyFrom(ArgBytes.data(), ArgBytes.size());
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

Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
autojit::RemoteEPC::createDefaultMemoryManager(RemoteEPC &SREPC) {
  EPCGenericJITLinkMemoryManager::SymbolAddrs SAs;
  if (auto Err = SREPC.getBootstrapSymbols(
          {{SAs.Allocator, rt::SimpleExecutorMemoryManagerInstanceName},
           {SAs.Reserve, rt::SimpleExecutorMemoryManagerReserveWrapperName},
           {SAs.Finalize, rt::SimpleExecutorMemoryManagerFinalizeWrapperName},
           {SAs.Deallocate,
            rt::SimpleExecutorMemoryManagerDeallocateWrapperName}}))
    return std::move(Err);

  return std::make_unique<EPCGenericJITLinkMemoryManager>(SREPC, SAs);
}

Expected<std::unique_ptr<MemoryAccess>>
autojit::RemoteEPC::createDefaultMemoryAccess(RemoteEPC &SREPC) {
  EPCGenericMemoryAccess::FuncAddrs FAs;
  if (auto Err = SREPC.getBootstrapSymbols(
          {{FAs.WriteUInt8s, rt::MemoryWriteUInt8sWrapperName},
           {FAs.WriteUInt16s, rt::MemoryWriteUInt16sWrapperName},
           {FAs.WriteUInt32s, rt::MemoryWriteUInt32sWrapperName},
           {FAs.WriteUInt64s, rt::MemoryWriteUInt64sWrapperName},
           {FAs.WriteBuffers, rt::MemoryWriteBuffersWrapperName},
           {FAs.WritePointers, rt::MemoryWritePointersWrapperName}}))
    return std::move(Err);

  return std::make_unique<EPCGenericMemoryAccess>(SREPC, FAs);
}

Error autojit::RemoteEPC::countSeqNo(uint64_t RemoteSeqNo) {
  uint64_t SeqNo = getNextSeqNo();
  if (RemoteSeqNo != SeqNo) {
#if !defined(NDEBUG)
    if (g_autojit_debug)
      return createStringError(inconvertibleErrorCode(),
                               "Expected sequence number %llu but got: %llu\n",
                               SeqNo, RemoteSeqNo);
#endif
    LOG() << "Warning: Expected sequence number " << SeqNo
          << " but got: " << RemoteSeqNo << "\n";
  }
  return Error::success();
}

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
      assert(!TagAddr && "Non-zero TagAddr for Result?");
      break;
    case SimpleRemoteEPCOpcode::CallWrapper:
      DBG() << "CallWrapper";
      break;
    }
    DBG() << ", seqno = " << SeqNo << ", tag-addr = " << TagAddr
           << ", arg-buffer = " << formatv("{0:x}", ArgBytes.size())
           << " bytes\n";
  }

  if (OpC == SimpleRemoteEPCOpcode::CallWrapper && TagAddr.getValue() == 0) {
    LOG() << "Warning: supress RPC invocation of nullptr\n";
    return Error::success();
  }

  return T->sendMessage(OpC, SeqNo, TagAddr, ArgBytes);
}

Error autojit::RemoteEPC::handleSetup(uint64_t RemoteSeqNo,
                                      ExecutorAddr TagAddr,
                                      SimpleRemoteEPCArgBytesVector ArgBytes) {
  // Keep sequence numbers in sync bi-directionally
  if (Error Err = countSeqNo(RemoteSeqNo))
    return Err;

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
      shared::WrapperFunctionResult::copyFrom(ArgBytes.data(), ArgBytes.size());
  SetupMsgHandler(std::move(WFR));
  return Error::success();
}

MSVCPError autojit::RemoteEPCExecutorInfo::deserialize(
    shared::WrapperFunctionResult Bytes) {
  if (const char *ErrMsg = Bytes.getOutOfBandError())
    return make_error<StringError>(ErrMsg, inconvertibleErrorCode());

  shared::SPSInputBuffer IB(Bytes.data(), Bytes.size());
  if (!shared::SPSArgList<SPSRemoteEPCExecutorInfo>::deserialize(IB, *this))
    return make_error<StringError>("Could not deserialize setup message",
                                   inconvertibleErrorCode());
  return Error::success();
}

static StringMap<ExecutorAddr> patchSymbolNames(StringMap<ExecutorAddr> Map) {
  auto RenameEntry = [&Map](StringRef From, StringRef To) {
    auto It = Map.find(From);
    if (It != Map.end()) {
      Map.try_emplace(To, It->second);
      Map.erase(It);
    }
  };

#if LLVM_VERSION_MAJOR < 21
  RenameEntry("llvm_orc_registerEHFrameAllocAction",
              "llvm_orc_registerEHFrameSectionWrapper");
  RenameEntry("llvm_orc_deregisterEHFrameAllocAction",
              "llvm_orc_deregisterEHFrameSectionWrapper");
#else
  RenameEntry("llvm_orc_registerEHFrameSectionWrapper",
              "llvm_orc_registerEHFrameAllocAction");
  RenameEntry("llvm_orc_deregisterEHFrameSectionWrapper",
              "llvm_orc_deregisterEHFrameAllocAction");
#endif

  return Map;
}

Error autojit::RemoteEPC::waitForSetup() {
  std::promise<MSVCPError> EIP;
  RemoteEPCExecutorInfo EI;
  auto EIF = EIP.get_future();

  // Prepare a handler for the setup packet.
  PendingCallWrapperResults[0] =
      RunInPlace()([&](shared::WrapperFunctionResult SetupMsgBytes) {
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
  this->BootstrapSymbols = patchSymbolNames(std::move(EI.BootstrapSymbols));
  this->HaveSupportedCxxStdlib = EI.hasSupportedCxxStdlib();

  // Get dispatch symbols for RPC calls back to the stub
  using namespace SimpleRemoteEPCDefaultBootstrapSymbolNames;
  if (auto Err = getBootstrapSymbols(
          {{JDI.JITDispatchContext, ExecutorSessionObjectName},
           {JDI.JITDispatchFunction, DispatchFnName}}))
    return Err;

  EPCDylibMgr = std::make_unique<EPCGenericDylibManager>(ExitOnErr(
      EPCGenericDylibManager::CreateWithDefaultBootstrapSymbols(*this)));

  OwnedMemMgr = ExitOnErr(createDefaultMemoryManager(*this));
  this->MemMgr = OwnedMemMgr.get();

  OwnedMemAccess = ExitOnErr(createDefaultMemoryAccess(*this));
  this->MemAccess = OwnedMemAccess.get();

  return Error::success();
}

Error autojit::RemoteEPC::sendSetupMessage(StringMap<ExecutorAddr> Symbols) {
  SimpleRemoteEPCExecutorInfo EI;
  EI.TargetTriple = sys::getProcessTriple();
  EI.PageSize = ExitOnErr(sys::Process::getPageSize());
  EI.BootstrapSymbols = std::move(Symbols);

  using SPSSerialize =
      shared::SPSArgList<shared::SPSSimpleRemoteEPCExecutorInfo>;
  auto SetupPacketBytes =
      shared::WrapperFunctionResult::allocate(SPSSerialize::size(EI));
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
                                       SimpleRemoteEPCArgBytesVector ArgBytes) {
  IncomingWFRHandler SendResult;

  if (TagAddr)
    return make_error<StringError>("Unexpected TagAddr in result message",
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

  auto WFR =
      shared::WrapperFunctionResult::copyFrom(ArgBytes.data(), ArgBytes.size());
  SendResult(std::move(WFR));
  return Error::success();
}

void autojit::RemoteEPC::handleCallWrapper(
    uint64_t RemoteSeqNo, ExecutorAddr TagAddr,
    SimpleRemoteEPCArgBytesVector ArgBytes) {
  assert(ES && "No ExecutionSession attached");
  D->dispatch(makeGenericNamedTask(
      [this, RemoteSeqNo, TagAddr, ArgBytes = std::move(ArgBytes)]() {
        // Keep sequence numbers in sync bi-directionally
        if (Error Err = countSeqNo(RemoteSeqNo))
          getExecutionSession().reportError(std::move(Err));

        // Call the wrapper function directly
        using WrapperFnTy =
            shared::CWrapperFunctionResult (*)(const char *, size_t);
        auto *Fn = TagAddr.toPtr<WrapperFnTy>();
        shared::WrapperFunctionResult WFR(Fn(ArgBytes.data(), ArgBytes.size()));

        // Check for out-of-band error before calling .data()
        const char *ErrMsg = WFR.getOutOfBandError();
        if (ErrMsg) {
          DBG() << "RPC function returned out-of-band error: " << ErrMsg
                << "\n";
          // For out-of-band errors, send the error as-is
          // The size is 0 and ValuePtr points to the error string
          if (auto Err =
                  sendMessage(SimpleRemoteEPCOpcode::Result, RemoteSeqNo,
                              ExecutorAddr(), {ErrMsg, strlen(ErrMsg) + 1}))
            getExecutionSession().reportError(std::move(Err));
        } else {
          if (auto Err = sendMessage(SimpleRemoteEPCOpcode::Result, RemoteSeqNo,
                                     ExecutorAddr(), {WFR.data(), WFR.size()}))
            getExecutionSession().reportError(std::move(Err));
        }
      },
      "callWrapper task"));
}
