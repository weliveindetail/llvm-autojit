#pragma once

#include "AutoJITConfig.h"

#include "runtime/core/AutoJIT.h"

#include <llvm/ADT/STLFunctionalExtras.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h>

#include <memory>

namespace autojit {

class RemoteEPC;
class Transport;

class Session {
public:
  Session(int InFD, int OutFD,
          std::unique_ptr<llvm::orc::ExecutionSession> &ES);
  ~Session();

  // OnReady runs before the stub learns about the RPC symbols. The stub calls
  // them as soon as it receives our setup message.
  void launch(std::unique_ptr<llvm::orc::ExecutionSession> ES,
              llvm::StringMap<llvm::orc::ExecutorAddr> Symbols,
              llvm::function_ref<void(autojit::AutoJIT *)> OnReady);
  int waitForDisconnect();

private:
  std::unique_ptr<Transport> Transport_;
  autojit::AutoJIT AutoJIT_;
  RemoteEPC *EPC_;
};

} // namespace autojit
