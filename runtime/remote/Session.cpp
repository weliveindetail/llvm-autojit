#include "runtime/remote/Session.h"
#include "AutoJITConfig.h"
#include "runtime/core/AutoJIT.h"

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

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace llvm;
using namespace llvm::orc;

static llvm::ExitOnError ExitOnErr("[autojitd] ");

namespace autojit {

class RemoteEPC : public ExecutorProcessControl,
                  public SimpleRemoteEPCTransportClient,
                  private DylibManager {
public:
  RemoteEPC(std::shared_ptr<SymbolStringPool> SSP,
            std::unique_ptr<TaskDispatcher> D)
      : ExecutorProcessControl(std::move(SSP), std::move(D)) {
    this->DylibMgr = this;
  }

  RemoteEPC(const RemoteEPC &) = delete;
  RemoteEPC &operator=(const RemoteEPC &) = delete;
  RemoteEPC(RemoteEPC &&) = delete;
  RemoteEPC &operator=(RemoteEPC &&) = delete;
  ~RemoteEPC();

  int waitForDisconnect();

  Expected<int32_t> runAsMain(ExecutorAddr, ArrayRef<std::string>) override {
    llvm_unreachable("Daemon is passive");
  }

  Expected<int32_t> runAsVoidFunction(ExecutorAddr) override {
    llvm_unreachable("Daemon is passive");
  }

  Expected<int32_t> runAsIntFunction(ExecutorAddr, int) override {
    llvm_unreachable("Daemon is passive");
  }

  Error disconnect() override { llvm_unreachable("Daemon is passive"); }

  void callWrapperAsync(ExecutorAddr WrapperFnAddr,
                        IncomingWFRHandler OnComplete,
                        ArrayRef<char> ArgBuffer) override;

  Expected<HandleMessageAction>
  handleMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo, ExecutorAddr TagAddr,
                SimpleRemoteEPCArgBytesVector ArgBytes) override;

  void handleDisconnect(Error Err) override;

  void setTransport(SimpleRemoteEPCTransport &T) { this->T = &T; }

  Error waitForSetup();

  static Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager(RemoteEPC &SREPC);
  static Expected<std::unique_ptr<MemoryAccess>>
  createDefaultMemoryAccess(RemoteEPC &SREPC);

  Error sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                    ExecutorAddr TagAddr, ArrayRef<char> ArgBytes);

private:
  Error handleSetup(uint64_t SeqNo, ExecutorAddr TagAddr,
                    SimpleRemoteEPCArgBytesVector ArgBytes);

  Error handleResult(uint64_t SeqNo, ExecutorAddr TagAddr,
                     SimpleRemoteEPCArgBytesVector ArgBytes);
  void handleCallWrapper(uint64_t RemoteSeqNo, ExecutorAddr TagAddr,
                         SimpleRemoteEPCArgBytesVector ArgBytes);

  uint64_t getNextSeqNo() { return NextSeqNo++; }
  void releaseSeqNo(uint64_t SeqNo) {}

  Expected<tpctypes::DylibHandle> loadDylib(const char *DylibPath) override;

  void lookupSymbolsAsync(ArrayRef<LookupRequest> Request,
                          SymbolLookupCompleteFn F) override;

  using PendingCallWrapperResultsMap = DenseMap<uint64_t, IncomingWFRHandler>;

  std::mutex ServerStateMutex;
  std::condition_variable DisconnectCV;
  Error DisconnectErr = Error::success();
  bool Disconnected = false;

  SimpleRemoteEPCTransport *T;
  std::unique_ptr<EPCGenericDylibManager> EPCDylibMgr;
  std::unique_ptr<jitlink::JITLinkMemoryManager> OwnedMemMgr;
  std::unique_ptr<MemoryAccess> OwnedMemAccess;

  uint64_t NextSeqNo = 0;
  PendingCallWrapperResultsMap PendingCallWrapperResults;
};

} // namespace autojit

autojit::Session::Session(int InFD, int OutFD,
                          std::unique_ptr<ExecutionSession> &ES) {
  auto SSP = std::make_shared<SymbolStringPool>();
  auto D = std::make_unique<DynamicThreadPoolTaskDispatcher>(std::nullopt);
  ES = std::make_unique<ExecutionSession>(
      std::make_unique<RemoteEPC>(std::move(SSP), std::move(D)));
  EPC_ = static_cast<RemoteEPC *>(&ES->getExecutorProcessControl());
  Transport_ =
      ExitOnErr(FDSimpleRemoteEPCTransport::Create(*EPC_, InFD, OutFD));
  EPC_->setTransport(*Transport_);
}

autojit::Session::~Session() {}

autojit::AutoJIT *
autojit::Session::launch(std::unique_ptr<llvm::orc::ExecutionSession> ES,
                         StringMap<ExecutorAddr> BootstrapSymbols) {
  ExitOnErr(EPC_->waitForSetup());

  LLJITBuilder Builder;
  Builder.setExecutionSession(std::move(ES));
  ExitOnErr(AutoJIT_.initialize(Builder));

  // Send setup message to the target process
  SimpleRemoteEPCExecutorInfo EI;
  EI.TargetTriple = sys::getProcessTriple();
  EI.PageSize = ExitOnErr(sys::Process::getPageSize());
  EI.BootstrapSymbols = std::move(BootstrapSymbols);

  using SPSSerialize =
      shared::SPSArgList<shared::SPSSimpleRemoteEPCExecutorInfo>;
  auto SetupPacketBytes =
      shared::WrapperFunctionResult::allocate(SPSSerialize::size(EI));
  shared::SPSOutputBuffer OB(SetupPacketBytes.data(), SetupPacketBytes.size());
  if (!SPSSerialize::serialize(OB, EI)) {
    LOG() << "Could not encode setup packet\n";
    exit(1);
  }

  ExitOnErr(Transport_->sendMessage(
      SimpleRemoteEPCOpcode::Setup, 0, ExecutorAddr(),
      {SetupPacketBytes.data(), SetupPacketBytes.size()}));
  return &AutoJIT_;
}

int autojit::Session::waitForDisconnect() { return EPC_->waitForDisconnect(); }

autojit::RemoteEPC::~RemoteEPC() {
#ifndef NDEBUG
  std::lock_guard<std::mutex> Lock(ServerStateMutex);
  assert(Disconnected && "Destroyed without disconnection");
#endif // NDEBUG
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
    dbgs() << "RemoteEPC::handleMessage: opc = ";
    switch (OpC) {
    case SimpleRemoteEPCOpcode::Setup:
      dbgs() << "Setup";
      assert(SeqNo == 0 && "Non-zero SeqNo for Setup?");
      assert(!TagAddr && "Non-zero TagAddr for Setup?");
      break;
    case SimpleRemoteEPCOpcode::Hangup:
      dbgs() << "Hangup";
      assert(SeqNo == 0 && "Non-zero SeqNo for Hangup?");
      assert(!TagAddr && "Non-zero TagAddr for Hangup?");
      break;
    case SimpleRemoteEPCOpcode::Result:
      dbgs() << "Result";
      assert(!TagAddr && "Non-zero TagAddr for Result?");
      break;
    case SimpleRemoteEPCOpcode::CallWrapper:
      dbgs() << "CallWrapper";
      break;
    }
    dbgs() << ", seqno = " << SeqNo << ", tag-addr = " << TagAddr
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
    return EndSession;
  }
  return ContinueSession;
}

void autojit::RemoteEPC::handleDisconnect(Error Err) {
  if (Err) {
    DBG() << "Disconnect error: " << toString(std::move(Err)) << "\n";
  }
  std::unique_lock<std::mutex> Lock(ServerStateMutex);
  Disconnected = true;
  DisconnectCV.notify_all();
}

int autojit::RemoteEPC::waitForDisconnect() {
  std::unique_lock<std::mutex> Lock(ServerStateMutex);
  DisconnectCV.wait(Lock, [this]() { return Disconnected; });
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

Expected<std::unique_ptr<ExecutorProcessControl::MemoryAccess>>
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

Error autojit::RemoteEPC::sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                                      ExecutorAddr TagAddr,
                                      ArrayRef<char> ArgBytes) {
  assert(OpC != SimpleRemoteEPCOpcode::Setup &&
         "RemoteEPC sending Setup message? That's the wrong direction.");

  {
    dbgs() << "RemoteEPC::sendMessage: opc = ";
    switch (OpC) {
    case SimpleRemoteEPCOpcode::Hangup:
      dbgs() << "Hangup";
      assert(SeqNo == 0 && "Non-zero SeqNo for Hangup?");
      assert(!TagAddr && "Non-zero TagAddr for Hangup?");
      break;
    case SimpleRemoteEPCOpcode::Result:
      dbgs() << "Result";
      assert(!TagAddr && "Non-zero TagAddr for Result?");
      break;
    case SimpleRemoteEPCOpcode::CallWrapper:
      dbgs() << "CallWrapper";
      break;
    default:
      llvm_unreachable("Invalid opcode");
    }
    dbgs() << ", seqno = " << SeqNo << ", tag-addr = " << TagAddr
           << ", arg-buffer = " << formatv("{0:x}", ArgBytes.size())
           << " bytes\n";
  }

  if (OpC == SimpleRemoteEPCOpcode::CallWrapper && TagAddr.getValue() == 0) {
    LOG() << "Warning: supressing invocation of nullptr in target process!\n";
    return Error::success(); // TODO: If we returned an error, is it rcoverable?
  }
  auto Err = T->sendMessage(OpC, SeqNo, TagAddr, ArgBytes);
  {
    if (Err)
      dbgs() << "  \\--> RemoteEPC::sendMessage failed\n";
  }
  return Err;
}

Error autojit::RemoteEPC::handleSetup(uint64_t SeqNo, ExecutorAddr TagAddr,
                                      SimpleRemoteEPCArgBytesVector ArgBytes) {
  if (SeqNo != 0)
    return make_error<StringError>("Setup packet SeqNo not zero",
                                   inconvertibleErrorCode());

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

Error autojit::RemoteEPC::waitForSetup() {
  std::promise<MSVCPExpected<SimpleRemoteEPCExecutorInfo>> EIP;
  auto EIF = EIP.get_future();

  // Prepare a handler for the setup packet.
  PendingCallWrapperResults[0] =
      RunInPlace()([&](shared::WrapperFunctionResult SetupMsgBytes) {
        if (const char *ErrMsg = SetupMsgBytes.getOutOfBandError()) {
          EIP.set_value(
              make_error<StringError>(ErrMsg, inconvertibleErrorCode()));
          return;
        }
        using SPSSerialize =
            shared::SPSArgList<shared::SPSSimpleRemoteEPCExecutorInfo>;
        shared::SPSInputBuffer IB(SetupMsgBytes.data(), SetupMsgBytes.size());
        SimpleRemoteEPCExecutorInfo EI;
        if (SPSSerialize::deserialize(IB, EI))
          EIP.set_value(EI);
        else
          EIP.set_value(make_error<StringError>(
              "Could not deserialize setup message", inconvertibleErrorCode()));
      });

  // Start the transport.
  if (auto Err = T->start())
    return Err;

  // Wait for setup packet to arrive.
  auto EI = EIF.get();
  if (!EI) {
    T->disconnect();
    return EI.takeError();
  }

  {
    dbgs() << "RemoteEPC received setup message:\n"
           << "  Triple: " << EI->TargetTriple << "\n"
           << "  Page size: " << EI->PageSize << "\n"
           << "  Bootstrap map" << (EI->BootstrapMap.empty() ? " empty" : ":")
           << "\n";
    for (const auto &KV : EI->BootstrapMap)
      dbgs() << "    " << KV.first() << ": " << KV.second.size()
             << "-byte SPS encoded buffer\n";
    dbgs() << "  Bootstrap symbols"
           << (EI->BootstrapSymbols.empty() ? " empty" : ":") << "\n";
    for (const auto &KV : EI->BootstrapSymbols)
      dbgs() << "    " << KV.first() << ": " << KV.second << "\n";
  }
  TargetTriple = Triple(EI->TargetTriple);
  PageSize = EI->PageSize;
  BootstrapMap = std::move(EI->BootstrapMap);
  BootstrapSymbols = std::move(EI->BootstrapSymbols);

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
