#pragma once

#include "AutoJITConfig.h"

#include <llvm/ExecutionEngine/Orc/Core.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/Support/Error.h>

namespace autojit {

// Bootstrap symbol for the GDB JIT registration, named like LLVM 24's
inline constexpr const char *GDBRegisterBootstrapName =
    "orc_rt_ci_aa_sps_GDBJITRegistrar_register";

class ExecutorPlatform {
public:
  ExecutorPlatform(bool EnableDebugging) : EnableDebugging(EnableDebugging) {}

  llvm::Expected<llvm::orc::JITDylibSP> operator()(llvm::orc::LLJIT &J);

private:
  bool EnableDebugging;
};

} // namespace autojit
