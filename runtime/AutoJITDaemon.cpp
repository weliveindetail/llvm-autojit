#include "AutoJITCommon.h"
#include "AutoJITConfig.h"

#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/EPCGenericDylibManager.h"
#include "llvm/ExecutionEngine/Orc/EPCGenericMemoryAccess.h"
#include "llvm/ExecutionEngine/Orc/Shared/SimplePackedSerialization.h"
#include "llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Host.h"

#include "llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManager.h"
#include "llvm/ExecutionEngine/Orc/Shared/OrcRTBridge.h"
#include "llvm/Support/FormatVariadic.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace llvm;
using namespace llvm::orc;

static llvm::ExitOnError ExitOnErr("[autojitd] ");
static ManagedStatic<std::unique_ptr<autojit::AutoJIT>> Instance;

extern "C" shared::CWrapperFunctionResult
autojit_rpc_register(const char *ArgData, size_t ArgSize) {
  using SPSArgList = shared::SPSArgList<shared::SPSString>;

  DBG() << "RPC register called with " << ArgSize << " bytes\n";
  DBG() << "First 16 bytes (hex): ";
  for (size_t i = 0; i < std::min(size_t(16), ArgSize); i++) {
    fprintf(stderr, "%02x ", (unsigned char)ArgData[i]);
  }
  fprintf(stderr, "\n");

  std::string FilePath;
  shared::SPSInputBuffer IB(ArgData, ArgSize);

  if (!SPSArgList::deserialize(IB, FilePath)) {
    DBG() << "Deserialization FAILED\n";
    return shared::WrapperFunctionResult::createOutOfBandError(
               "Failed to deserialize arguments")
        .release();
  }

  DBG() << "RPC register module: " << FilePath << "\n";

  // In daemon mode, load the module directly into the JIT instead of using
  // ModulesRegistered_ The JIT should already be initialized by the time we get
  // here
  if (!Instance.isConstructed())
    return shared::WrapperFunctionResult::createOutOfBandError(
               "JIT not initialized")
        .release();

  // Load the module (we'll need to implement this in AutoJIT)
  ThreadSafeModule TSM = Instance->get()->loadModule(FilePath);
  if (Error Err = Instance->get()->submit(std::move(TSM))) {
    std::string Message = toString(std::move(Err));
    DBG() << "Loading FAILED: " << Message << "\n";
    return shared::WrapperFunctionResult::createOutOfBandError(
               "Failed to load module")
        .release();
  }

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

  if (!Instance.isConstructed())
    return shared::WrapperFunctionResult::createOutOfBandError(
               "JIT not initialized")
        .release();

  std::string Name = autojit::guidToFnName(Guid);
  DBG() << "Lookup function: " << Name << "\n";

  uint64_t Addr = Instance->get()->lookup(Name.c_str());
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

class SimpleRemoteEPC : public ExecutorProcessControl,
                        public SimpleRemoteEPCTransportClient,
                        private DylibManager {
public:
  /// A setup object containing callbacks to construct a memory manager and
  /// memory access object. Both are optional. If not specified,
  /// EPCGenericJITLinkMemoryManager and EPCGenericMemoryAccess will be used.
  struct Setup {
    using CreateMemoryManagerFn =
        Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>(
            SimpleRemoteEPC &);
    using CreateMemoryAccessFn =
        Expected<std::unique_ptr<MemoryAccess>>(SimpleRemoteEPC &);

    unique_function<CreateMemoryManagerFn> CreateMemoryManager;
    unique_function<CreateMemoryAccessFn> CreateMemoryAccess;
  };

  SimpleRemoteEPC(std::shared_ptr<SymbolStringPool> SSP,
                  std::unique_ptr<TaskDispatcher> D)
      : ExecutorProcessControl(std::move(SSP), std::move(D)) {
    this->DylibMgr = this;
  }

  SimpleRemoteEPC(const SimpleRemoteEPC &) = delete;
  SimpleRemoteEPC &operator=(const SimpleRemoteEPC &) = delete;
  SimpleRemoteEPC(SimpleRemoteEPC &&) = delete;
  SimpleRemoteEPC &operator=(SimpleRemoteEPC &&) = delete;
  ~SimpleRemoteEPC();

  Expected<int32_t> runAsMain(ExecutorAddr MainFnAddr,
                              ArrayRef<std::string> Args) override;

  Expected<int32_t> runAsVoidFunction(ExecutorAddr VoidFnAddr) override;

  Expected<int32_t> runAsIntFunction(ExecutorAddr IntFnAddr, int Arg) override;

  void callWrapperAsync(ExecutorAddr WrapperFnAddr,
                        IncomingWFRHandler OnComplete,
                        ArrayRef<char> ArgBuffer) override;

  Error disconnect() override;

  Expected<HandleMessageAction>
  handleMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo, ExecutorAddr TagAddr,
                SimpleRemoteEPCArgBytesVector ArgBytes) override;

  void handleDisconnect(Error Err) override;

  void setTransport(SimpleRemoteEPCTransport &T) { this->T = &T; }

  Error setup(Setup S);

  static Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager(SimpleRemoteEPC &SREPC);
  static Expected<std::unique_ptr<MemoryAccess>>
  createDefaultMemoryAccess(SimpleRemoteEPC &SREPC);

  Error sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                    ExecutorAddr TagAddr, ArrayRef<char> ArgBytes);

private:
  Error handleSetup(uint64_t SeqNo, ExecutorAddr TagAddr,
                    SimpleRemoteEPCArgBytesVector ArgBytes);

  Error handleResult(uint64_t SeqNo, ExecutorAddr TagAddr,
                     SimpleRemoteEPCArgBytesVector ArgBytes);
  void handleCallWrapper(uint64_t RemoteSeqNo, ExecutorAddr TagAddr,
                         SimpleRemoteEPCArgBytesVector ArgBytes);
  Error handleHangup(SimpleRemoteEPCArgBytesVector ArgBytes);

  uint64_t getNextSeqNo() { return NextSeqNo++; }
  void releaseSeqNo(uint64_t SeqNo) {}

  Expected<tpctypes::DylibHandle> loadDylib(const char *DylibPath) override;

  void lookupSymbolsAsync(ArrayRef<LookupRequest> Request,
                          SymbolLookupCompleteFn F) override;

  using PendingCallWrapperResultsMap = DenseMap<uint64_t, IncomingWFRHandler>;

  std::mutex SimpleRemoteEPCMutex;
  std::condition_variable DisconnectCV;
  bool Disconnected = false;
  Error DisconnectErr = Error::success();

  SimpleRemoteEPCTransport *T;
  std::unique_ptr<jitlink::JITLinkMemoryManager> OwnedMemMgr;
  std::unique_ptr<MemoryAccess> OwnedMemAccess;

  std::unique_ptr<EPCGenericDylibManager> EPCDylibMgr;
  ExecutorAddr RunAsMainAddr;
  ExecutorAddr RunAsVoidFunctionAddr;
  ExecutorAddr RunAsIntFunctionAddr;

  uint64_t NextSeqNo = 0;
  PendingCallWrapperResultsMap PendingCallWrapperResults;
};

SimpleRemoteEPC::~SimpleRemoteEPC() {
#ifndef NDEBUG
  std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
  assert(Disconnected && "Destroyed without disconnection");
#endif // NDEBUG
}

Expected<tpctypes::DylibHandle>
SimpleRemoteEPC::loadDylib(const char *DylibPath) {
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

void SimpleRemoteEPC::lookupSymbolsAsync(ArrayRef<LookupRequest> Request,
                                         SymbolLookupCompleteFn Complete) {
  lookupSymbolsAsyncHelper(*EPCDylibMgr, Request, {}, std::move(Complete));
}

Expected<int32_t> SimpleRemoteEPC::runAsMain(ExecutorAddr MainFnAddr,
                                             ArrayRef<std::string> Args) {
  int64_t Result = 0;
  if (auto Err = callSPSWrapper<rt::SPSRunAsMainSignature>(
          RunAsMainAddr, Result, MainFnAddr, Args))
    return std::move(Err);
  return Result;
}

Expected<int32_t> SimpleRemoteEPC::runAsVoidFunction(ExecutorAddr VoidFnAddr) {
  int32_t Result = 0;
  if (auto Err = callSPSWrapper<rt::SPSRunAsVoidFunctionSignature>(
          RunAsVoidFunctionAddr, Result, VoidFnAddr))
    return std::move(Err);
  return Result;
}

Expected<int32_t> SimpleRemoteEPC::runAsIntFunction(ExecutorAddr IntFnAddr,
                                                    int Arg) {
  int32_t Result = 0;
  if (auto Err = callSPSWrapper<rt::SPSRunAsIntFunctionSignature>(
          RunAsIntFunctionAddr, Result, IntFnAddr, Arg))
    return std::move(Err);
  return Result;
}

void SimpleRemoteEPC::callWrapperAsync(ExecutorAddr WrapperFnAddr,
                                       IncomingWFRHandler OnComplete,
                                       ArrayRef<char> ArgBuffer) {
  uint64_t SeqNo;
  {
    std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
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
      std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
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

Error SimpleRemoteEPC::disconnect() {
  T->disconnect();
  D->shutdown();
  std::unique_lock<std::mutex> Lock(SimpleRemoteEPCMutex);
  DisconnectCV.wait(Lock, [this] { return Disconnected; });
  return std::move(DisconnectErr);
}

Expected<SimpleRemoteEPCTransportClient::HandleMessageAction>
SimpleRemoteEPC::handleMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                               ExecutorAddr TagAddr,
                               SimpleRemoteEPCArgBytesVector ArgBytes) {

  {
    dbgs() << "SimpleRemoteEPC::handleMessage: opc = ";
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
  case SimpleRemoteEPCOpcode::Hangup:
    T->disconnect();
    if (auto Err = handleHangup(std::move(ArgBytes)))
      return std::move(Err);
    return EndSession;
  case SimpleRemoteEPCOpcode::Result:
    if (auto Err = handleResult(SeqNo, TagAddr, std::move(ArgBytes)))
      return std::move(Err);
    break;
  case SimpleRemoteEPCOpcode::CallWrapper:
    handleCallWrapper(SeqNo, TagAddr, std::move(ArgBytes));
    break;
  }
  return ContinueSession;
}

void SimpleRemoteEPC::handleDisconnect(Error Err) {
  {
    dbgs() << "SimpleRemoteEPC::handleDisconnect: "
           << (Err ? "failure" : "success") << "\n";
  }

  PendingCallWrapperResultsMap TmpPending;

  {
    std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
    std::swap(TmpPending, PendingCallWrapperResults);
  }

  for (auto &KV : TmpPending)
    KV.second(
        shared::WrapperFunctionResult::createOutOfBandError("disconnecting"));

  std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
  DisconnectErr = joinErrors(std::move(DisconnectErr), std::move(Err));
  Disconnected = true;
  DisconnectCV.notify_all();
}

Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
SimpleRemoteEPC::createDefaultMemoryManager(SimpleRemoteEPC &SREPC) {
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
SimpleRemoteEPC::createDefaultMemoryAccess(SimpleRemoteEPC &SREPC) {
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

Error SimpleRemoteEPC::sendMessage(SimpleRemoteEPCOpcode OpC, uint64_t SeqNo,
                                   ExecutorAddr TagAddr,
                                   ArrayRef<char> ArgBytes) {
  assert(OpC != SimpleRemoteEPCOpcode::Setup &&
         "SimpleRemoteEPC sending Setup message? That's the wrong direction.");

  {
    dbgs() << "SimpleRemoteEPC::sendMessage: opc = ";
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
  auto Err = T->sendMessage(OpC, SeqNo, TagAddr, ArgBytes);
  {
    if (Err)
      dbgs() << "  \\--> SimpleRemoteEPC::sendMessage failed\n";
  }
  return Err;
}

Error SimpleRemoteEPC::handleSetup(uint64_t SeqNo, ExecutorAddr TagAddr,
                                   SimpleRemoteEPCArgBytesVector ArgBytes) {
  if (SeqNo != 0)
    return make_error<StringError>("Setup packet SeqNo not zero",
                                   inconvertibleErrorCode());

  if (TagAddr)
    return make_error<StringError>("Setup packet TagAddr not zero",
                                   inconvertibleErrorCode());

  std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
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

Error SimpleRemoteEPC::setup(Setup S) {
  using namespace SimpleRemoteEPCDefaultBootstrapSymbolNames;

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
    dbgs() << "SimpleRemoteEPC received setup message:\n"
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
  if (auto Err = getBootstrapSymbols(
          {{JDI.JITDispatchContext, ExecutorSessionObjectName},
           {JDI.JITDispatchFunction, DispatchFnName}}))
    return Err;

  // Note: We don't need RunAsMain/VoidFunction/IntFunction wrappers for AutoJIT
  // since we're not running programs in the executor, just compiling and
  // returning function addresses.

  if (auto DM =
          EPCGenericDylibManager::CreateWithDefaultBootstrapSymbols(*this))
    EPCDylibMgr = std::make_unique<EPCGenericDylibManager>(std::move(*DM));
  else
    return DM.takeError();

  // Set a default CreateMemoryManager if none is specified.
  if (!S.CreateMemoryManager)
    S.CreateMemoryManager = createDefaultMemoryManager;

  if (auto MemMgr = S.CreateMemoryManager(*this)) {
    OwnedMemMgr = std::move(*MemMgr);
    this->MemMgr = OwnedMemMgr.get();
  } else
    return MemMgr.takeError();

  // Set a default CreateMemoryAccess if none is specified.
  if (!S.CreateMemoryAccess)
    S.CreateMemoryAccess = createDefaultMemoryAccess;

  if (auto MemAccess = S.CreateMemoryAccess(*this)) {
    OwnedMemAccess = std::move(*MemAccess);
    this->MemAccess = OwnedMemAccess.get();
  } else
    return MemAccess.takeError();

  return Error::success();
}

Error SimpleRemoteEPC::handleResult(uint64_t SeqNo, ExecutorAddr TagAddr,
                                    SimpleRemoteEPCArgBytesVector ArgBytes) {
  IncomingWFRHandler SendResult;

  if (TagAddr)
    return make_error<StringError>("Unexpected TagAddr in result message",
                                   inconvertibleErrorCode());

  {
    std::lock_guard<std::mutex> Lock(SimpleRemoteEPCMutex);
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

void SimpleRemoteEPC::handleCallWrapper(
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

Error SimpleRemoteEPC::handleHangup(SimpleRemoteEPCArgBytesVector ArgBytes) {
  using namespace llvm::orc::shared;
  auto WFR = WrapperFunctionResult::copyFrom(ArgBytes.data(), ArgBytes.size());
  if (const char *ErrMsg = WFR.getOutOfBandError())
    return make_error<StringError>(ErrMsg, inconvertibleErrorCode());

  shared::detail::SPSSerializableError Info;
  SPSInputBuffer IB(WFR.data(), WFR.size());
  if (!SPSArgList<SPSError>::deserialize(IB, Info))
    return make_error<StringError>("Could not deserialize hangup info",
                                   inconvertibleErrorCode());
  return fromSPSSerializable(std::move(Info));
}

// Right now the daemon is always forked as a child process
int main(int argc, char *argv[]) {
  autojit::initializeDebugLog();
  DBG() << "Starting daemon\n";

  auto SSP = std::make_shared<SymbolStringPool>();
  auto D = std::make_unique<DynamicThreadPoolTaskDispatcher>(std::nullopt);
  auto ES = std::make_unique<ExecutionSession>(
      std::make_unique<SimpleRemoteEPC>(std::move(SSP), std::move(D)));
  auto &EPC = static_cast<SimpleRemoteEPC &>(ES->getExecutorProcessControl());
  auto T = ExitOnErr(
      FDSimpleRemoteEPCTransport::Create(EPC, STDIN_FILENO, STDOUT_FILENO));

  // Read from stdin, write to stdout
  EPC.setTransport(*T);

  // Send setup message to the target process
  std::vector<char> SetupPacket;
  SimpleRemoteEPCExecutorInfo EI;
  EI.TargetTriple = sys::getProcessTriple();
  EI.PageSize = ExitOnErr(sys::Process::getPageSize());
  EI.BootstrapSymbols["autojit_rpc_register"] =
      ExecutorAddr::fromPtr(autojit_rpc_register);
  EI.BootstrapSymbols["autojit_rpc_materialize"] =
      ExecutorAddr::fromPtr(autojit_rpc_materialize);

  using SPSSerialize =
      shared::SPSArgList<shared::SPSSimpleRemoteEPCExecutorInfo>;
  auto SetupPacketBytes =
      shared::WrapperFunctionResult::allocate(SPSSerialize::size(EI));
  shared::SPSOutputBuffer OB(SetupPacketBytes.data(), SetupPacketBytes.size());
  if (!SPSSerialize::serialize(OB, EI)) {
    LOG() << "Could not encode setup packet\n";
    exit(1);
  }

  ExitOnErr(T->sendMessage(SimpleRemoteEPCOpcode::Setup, 0, ExecutorAddr(),
                           {SetupPacketBytes.data(), SetupPacketBytes.size()}));

  // Receive the setup message from the target process
  SimpleRemoteEPC::Setup S;
  S.CreateMemoryAccess = SimpleRemoteEPC::createDefaultMemoryAccess;
  S.CreateMemoryManager = SimpleRemoteEPC::createDefaultMemoryManager;
  ExitOnErr(EPC.setup(std::move(S)));

  LLJITBuilder Builder;
  Builder.setExecutionSession(std::move(ES));
  *Instance = std::make_unique<autojit::AutoJIT>(Builder);

  // TODO: We need something like waitForDisconnect()
  DBG() << "Daemon entering event loop\n";
  while (true) ;

  DBG() << "Host disconnected, daemon shutting down\n";
  return 0;
}
