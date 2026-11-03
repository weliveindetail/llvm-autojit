#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// AutoJIT runtime function to materialize a user function that the plugin
/// outlined at compile-time. Guid was selected for the function at
/// compile-time. Module is the descriptor of its lazy module (see
/// common/LazyModule.h), which the runtime loads on first use. Returns the
/// address of the finalized function in memory and stores it to Slot. Slot
/// only ever holds null or the final address.
///
void *__llvm_autojit_materialize(void **Slot, uint64_t Guid,
                                  const void *Module);

#ifdef __cplusplus
}
#endif
