#pragma once

#include "runtime/core/AutoJIT.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h>

namespace autojit {

class RemoteEPC;
class Transport;

class Session {
public:
  Session(int InFD, int OutFD,
          std::unique_ptr<llvm::orc::ExecutionSession> &ES);
  ~Session();

  autojit::AutoJIT *launch(std::unique_ptr<llvm::orc::ExecutionSession> ES,
                           llvm::StringMap<llvm::orc::ExecutorAddr> Symbols);
  int waitForDisconnect();

private:
  std::unique_ptr<Transport> Transport_;
  autojit::AutoJIT AutoJIT_;
  RemoteEPC *EPC_;
};

} // namespace autojit
