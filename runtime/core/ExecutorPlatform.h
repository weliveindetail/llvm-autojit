#pragma once

#include "AutoJITConfig.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/Support/Error.h>

namespace autojit {

class ExecutorPlatform {
public:
  ExecutorPlatform(bool EnableDebugging, bool HaveOrcRuntimeDeps)
      : EnableDebugging(EnableDebugging),
        HaveOrcRuntimeDeps(HaveOrcRuntimeDeps) {}

  llvm::Expected<llvm::orc::JITDylibSP> operator()(llvm::orc::LLJIT &J);

private:
  bool EnableDebugging;
  bool HaveOrcRuntimeDeps;
};

} // namespace autojit
