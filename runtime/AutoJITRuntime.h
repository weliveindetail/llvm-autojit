#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/// AutoJIT runtime function that materializes (loads and executes) the original
/// implementation of a function from an IR file.
///
/// \param FuncName The name of the function to materialize
/// \param FilePath The path to the IR file (.bc or .ll) containing the original
/// function
/// \param FuncPtrAddr Address of the function pointer to patch with the
/// materialized function
void __llvm_autojit_materialize(void **GuidInPtrOut);

/// AutoJIT runtime function that registers a module for lazy loading.
/// This function is called by static initializers injected by the AutoJIT
/// plugin.
///
/// \param FilePath The path to the IR file (.bc or .ll) containing the module
void __llvm_autojit_register(const char *FilePath);

#ifdef __cplusplus
}
#endif
