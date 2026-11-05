#ifndef AUTOJIT_RUNTIME_CORE_ORCCOMPAT_H
#define AUTOJIT_RUNTIME_CORE_ORCCOMPAT_H

// ORC was reworked between LLVM 21 and 24

#include <llvm/Config/llvm-config.h>
#include <llvm/ExecutionEngine/Orc/Shared/WrapperFunctionUtils.h>

#if LLVM_VERSION_MAJOR >= 24
#define AUTOJIT_ORC_V24 1
#else
#define AUTOJIT_ORC_V24 0
#endif

namespace autojit {
#if AUTOJIT_ORC_V24
using WFBuffer = llvm::orc::shared::WrapperFunctionBuffer;
using CWFBuffer = llvm::orc::shared::CWrapperFunctionBuffer;
#else
using WFBuffer = llvm::orc::shared::WrapperFunctionResult;
using CWFBuffer = llvm::orc::shared::CWrapperFunctionResult;
#endif
} // namespace autojit

#endif // AUTOJIT_RUNTIME_CORE_ORCCOMPAT_H
