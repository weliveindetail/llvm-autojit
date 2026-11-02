#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// AutoJIT runtime function to materialize a user function that the plugin
/// outlined at compile-time. Guid was selected for the function at
/// compile-time. Returns the address of the finalized function in memory and
/// stores it to Slot. Slot only ever holds null or the final address.
///
void *__llvm_autojit_materialize(void **Slot, uint64_t Guid);

/// AutoJIT runtime function to register a module with user functions. The
/// plugin injects a self-registration initializer into each module that calls
/// this function at load-time. ImportTable points to the module's table of
/// imported symbols (see common/ImportTable.h).
///
void __llvm_autojit_register2(const char *FilePath, const void *ImportTable);

#ifdef __cplusplus
}
#endif
