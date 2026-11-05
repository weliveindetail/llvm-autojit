#include "runtime/remote/RemoteEPC.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/DylibManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericDylibManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericMemoryAccess.h>
#include <llvm/ExecutionEngine/Orc/MemoryAccess.h>
#include <llvm/ExecutionEngine/Orc/Shared/OrcRTBridge.h>
#include <llvm/ExecutionEngine/Orc/Shared/SimplePackedSerialization.h>

// Previous LLVM versions, DefaultRemoteEPC.cpp tracks mainline

using namespace llvm;
using namespace llvm::orc;
using MemoryAccess = llvm::orc::MemoryAccess;

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

  // LLVM 21 and 23 look up the EH frame alloc actions by these names
  RenameEntry("orc_rt_ci_aa_sps_DWARFEHFrameRegistrar_registerSection",
              rt::RegisterEHFrameSectionAllocActionName);
  RenameEntry("orc_rt_ci_aa_sps_DWARFEHFrameRegistrar_deregisterSection",
              rt::DeregisterEHFrameSectionAllocActionName);
#if AUTOJIT_LLVM_23
  RenameEntry("orc_rt_ci_aa_sps_GDBJITRegistrar_register",
              rt::RegisterJITLoaderGDBAllocActionName);
#endif

  return Map;
}

namespace autojit {

#if AUTOJIT_LLVM_21
// The stub's dylib manager has mainline's interface
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

// The stub speaks mainline's interface, so we map it to older versions
class LegacyRemoteEPC : public RemoteEPC {
public:
  using RemoteEPC::RemoteEPC;

  Expected<int32_t> runAsVoidFunction(ExecutorAddr) override {
    llvm_unreachable("Daemon is passive");
  }

  Expected<int32_t> runAsIntFunction(ExecutorAddr, int) override {
    llvm_unreachable("Daemon is passive");
  }

#if AUTOJIT_LLVM_23
  Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager() override {
    return createLegacyMemoryManager();
  }
  Expected<std::unique_ptr<DylibManager>> createDefaultDylibMgr() override {
    return createLegacyDylibMgr();
  }
  Expected<std::unique_ptr<MemoryAccess>> createDefaultMemoryAccess() override {
    return createLegacyMemoryAccess();
  }
#endif

private:
  Error finishSetup() override;

  Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createLegacyMemoryManager();
  Expected<std::unique_ptr<DylibManager>> createLegacyDylibMgr();
  Expected<std::unique_ptr<MemoryAccess>> createLegacyMemoryAccess();

#if AUTOJIT_LLVM_21
  // The EPC owns its managers in LLVM 21
  std::unique_ptr<DylibManager> OwnedDylibMgr;
  std::unique_ptr<jitlink::JITLinkMemoryManager> OwnedMemMgr;
  std::unique_ptr<MemoryAccess> OwnedMemAccess;
#endif
};

} // namespace autojit

#if AUTOJIT_LLVM_21
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

Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
autojit::LegacyRemoteEPC::createLegacyMemoryManager() {
#if AUTOJIT_LLVM_21
  EPCGenericJITLinkMemoryManager::SymbolAddrs SAs;
  if (auto Err = getBootstrapSymbols(
          {{SAs.Allocator, "orc_rt_ci_SimpleNativeMemoryMap_Instance"},
           {SAs.Reserve, "orc_rt_ci_sps_SimpleNativeMemoryMap_reserve"},
           // The stub keeps the old finalize for us, mainline initializes
           {SAs.Finalize, rt::SimpleExecutorMemoryManagerFinalizeWrapperName},
           // Release runs the dealloc actions, like deallocate
           {SAs.Deallocate,
            "orc_rt_ci_sps_SimpleNativeMemoryMap_releaseMultiple"}}))
    return std::move(Err);

  return std::make_unique<EPCGenericJITLinkMemoryManager>(*this, SAs);
#else
  return EPCGenericJITLinkMemoryManager::Create(getExecutionSession());
#endif
}

Expected<std::unique_ptr<DylibManager>>
autojit::LegacyRemoteEPC::createLegacyDylibMgr() {
#if AUTOJIT_LLVM_21
  return LegacyDylibManager::Create(*this);
#else
  auto DM = EPCGenericDylibManager::Create(getExecutionSession());
  if (!DM)
    return DM.takeError();
  return std::make_unique<EPCGenericDylibManager>(std::move(*DM));
#endif
}

// The stub doesn't implement reads
Expected<std::unique_ptr<MemoryAccess>>
autojit::LegacyRemoteEPC::createLegacyMemoryAccess() {
  EPCGenericMemoryAccess::FuncAddrs FAs;
  if (auto Err = getBootstrapSymbols(
          {{FAs.WriteUInt8s, "orc_rt_ci_sps_mem_write_uint8s"},
           {FAs.WriteUInt16s, "orc_rt_ci_sps_mem_write_uint16s"},
           {FAs.WriteUInt32s, "orc_rt_ci_sps_mem_write_uint32s"},
           {FAs.WriteUInt64s, "orc_rt_ci_sps_mem_write_uint64s"},
           {FAs.WriteBuffers, "orc_rt_ci_sps_mem_write_buffers"},
           {FAs.WritePointers, "orc_rt_ci_sps_mem_write_pointers"}}))
    return std::move(Err);
  return std::make_unique<EPCGenericMemoryAccess>(*this, FAs);
}

Error autojit::LegacyRemoteEPC::finishSetup() {
  this->BootstrapSymbols = patchSymbolNames(std::move(this->BootstrapSymbols));

#if AUTOJIT_LLVM_21
  // Get dispatch symbols for RPC calls back to the stub
  if (auto Err = getBootstrapSymbols(
          {{JDI.JITDispatchContext, "__orc_rt_jit_dispatch_ctx"},
           {JDI.JITDispatchFunction, "__orc_rt_jit_dispatch"}}))
    return Err;

  auto DM = createLegacyDylibMgr();
  if (!DM)
    return DM.takeError();
  OwnedDylibMgr = std::move(*DM);
  this->DylibMgr = OwnedDylibMgr.get();

  auto MM = createLegacyMemoryManager();
  if (!MM)
    return MM.takeError();
  OwnedMemMgr = std::move(*MM);
  this->MemMgr = OwnedMemMgr.get();

  auto MA = createLegacyMemoryAccess();
  if (!MA)
    return MA.takeError();
  OwnedMemAccess = std::move(*MA);
  this->MemAccess = OwnedMemAccess.get();

  return Error::success();
#else
  // The session copied the bootstrap symbols when we created it, before we
  // received them
  SymbolMap Symbols;
  for (const auto &[Name, Addr] : this->BootstrapSymbols)
    Symbols[ES->intern(Name)] = {Addr, JITSymbolFlags::Exported};
  return ES->getBootstrapJITDylib().define(absoluteSymbols(std::move(Symbols)));
#endif
}

std::unique_ptr<autojit::RemoteEPC>
autojit::createSessionEPC(std::shared_ptr<SymbolStringPool> SSP,
                          std::unique_ptr<TaskDispatcher> D) {
  return std::make_unique<LegacyRemoteEPC>(std::move(SSP), std::move(D));
}
