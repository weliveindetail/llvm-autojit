#ifndef AUTOJIT_RUNTIME_CORE_ORCCOMPAT_H
#define AUTOJIT_RUNTIME_CORE_ORCCOMPAT_H

// ORC was reworked between LLVM 21 and 24

#include <llvm/Config/llvm-config.h>
#include <llvm/ExecutionEngine/Orc/Shared/WrapperFunctionUtils.h>

// Guards legacy code, LLVM 24 is the default
#if LLVM_VERSION_MAJOR == 21
#define AUTOJIT_LLVM_21 1
#else
#define AUTOJIT_LLVM_21 0
#endif

namespace autojit {
#if AUTOJIT_LLVM_21
using WFBuffer = llvm::orc::shared::WrapperFunctionResult;
using CWFBuffer = llvm::orc::shared::CWrapperFunctionResult;
#else
using WFBuffer = llvm::orc::shared::WrapperFunctionBuffer;
using CWFBuffer = llvm::orc::shared::CWrapperFunctionBuffer;
#endif
} // namespace autojit

#endif // AUTOJIT_RUNTIME_CORE_ORCCOMPAT_H
