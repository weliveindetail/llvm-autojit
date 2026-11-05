#include "runtime/remote/RemoteEPC.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/DylibManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericDylibManagerSPS.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManager.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManagerSPS.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericMemoryAccess.h>
#include <llvm/ExecutionEngine/Orc/EPCGenericMemoryAccessSPS.h>
#include <llvm/ExecutionEngine/Orc/LookupAndApply.h>
#include <llvm/ExecutionEngine/Orc/MemoryAccess.h>
#include <llvm/ExecutionEngine/Orc/RecordProxy.h>

// Mainline implementation, LegacyRemoteEPC.cpp covers older versions

using namespace llvm;
using namespace llvm::orc;
using MemoryAccess = llvm::orc::MemoryAccess;

namespace autojit {

class DefaultRemoteEPC : public RemoteEPC {
public:
  using RemoteEPC::RemoteEPC;

  Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
  createDefaultMemoryManager() override;
  Expected<std::unique_ptr<DylibManager>> createDefaultDylibMgr() override;
  Expected<std::unique_ptr<MemoryAccess>> createDefaultMemoryAccess() override;

private:
  Error finishSetup() override;
};

} // namespace autojit

Expected<std::unique_ptr<jitlink::JITLinkMemoryManager>>
autojit::DefaultRemoteEPC::createDefaultMemoryManager() {
  return sps::createEPCGenericJITLinkMemoryManager(getExecutionSession());
}

Expected<std::unique_ptr<DylibManager>>
autojit::DefaultRemoteEPC::createDefaultDylibMgr() {
  return sps::createEPCGenericDylibManager(getExecutionSession());
}

// The stub doesn't implement reads
Expected<std::unique_ptr<MemoryAccess>>
autojit::DefaultRemoteEPC::createDefaultMemoryAccess() {
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

// The session copied the bootstrap symbols when we created it, before we
// received them
Error autojit::DefaultRemoteEPC::finishSetup() {
  SymbolMap Symbols;
  for (const auto &[Name, Addr] : this->BootstrapSymbols)
    Symbols[ES->intern(Name)] = {Addr, JITSymbolFlags::Exported};
  return ES->getBootstrapJITDylib().define(absoluteSymbols(std::move(Symbols)));
}

std::unique_ptr<autojit::RemoteEPC>
autojit::createSessionEPC(std::shared_ptr<SymbolStringPool> SSP,
                          std::unique_ptr<TaskDispatcher> D) {
  return std::make_unique<DefaultRemoteEPC>(std::move(SSP), std::move(D));
}
