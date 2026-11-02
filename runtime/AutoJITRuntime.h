#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/// AutoJIT runtime function to materialize a user function that the plugin
/// outlined at compile-time. The incoming value for the sole parameter points
/// to the GUID that was selected for the function at compile-time. The outgoing
/// value is the address of the finalized function in memory.
///
void __llvm_autojit_materialize(void **GuidInPtrOut);

/// AutoJIT runtime function to register a module with user functions. The
/// plugin injects a self-registration initializer into each module that calls
/// this function at load-time. ImportTable points to the module's table of
/// imported symbols (see common/ImportTable.h).
///
void __llvm_autojit_register2(const char *FilePath, const void *ImportTable);

#ifdef __cplusplus
}
#endif
