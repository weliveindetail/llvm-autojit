#pragma once

/* Descriptor of a lazy module that the plugin emits into each static object.
 * Trampolines pass it to the runtime when they materialize a function, so the
 * runtime loads lazy modules on demand.
 *
 * It lists the addresses of all symbols that the lazy module imports from the
 * host process. The runtime derives the matching names from the lazy module
 * itself (see Imports.h), so the binary doesn't need to store them.
 *
 * Layout:
 *   header
 *   int32_t entries[num_imports]     offset from the entry to its target
 *   uint8_t indirect[(num_imports + 7) / 8]
 *   char path[]                      null-terminated path of the lazy module
 *
 * Direct entries point to the symbol itself. Indirect entries point to a slot
 * that holds the symbol's address, usually a GOT entry. The descriptor has no
 * relocations that the dynamic loader would have to process. The format must
 * be readable from C, because the static stub is pure C.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define AUTOJIT_LAZY_MODULE_VERSION 2

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t version;
  uint32_t num_imports;
  /* Hash of the lazy module file contents, to detect stale lazy modules */
  uint64_t hash;
} autojit_lazy_module_t;

/* Data that x86-64 trampolines store after their jump. They pass its address
 * to the resolver in r11. Offsets are relative to the start of the entry. */
typedef struct {
  uint64_t guid;
  int32_t slot_offset;
  int32_t module_offset;
} autojit_trampoline_entry_t;

static inline const int32_t *
autojit_import_entries(const autojit_lazy_module_t *module) {
  return (const int32_t *)(module + 1);
}

static inline const uint8_t *
autojit_import_indirect(const autojit_lazy_module_t *module) {
  return (const uint8_t *)(autojit_import_entries(module) +
                           module->num_imports);
}

static inline const char *
autojit_lazy_module_path(const autojit_lazy_module_t *module) {
  return (const char *)(autojit_import_indirect(module) +
                        (module->num_imports + 7) / 8);
}

static inline uint64_t
autojit_import_address(const autojit_lazy_module_t *module, uint32_t idx) {
  const int32_t *entry = autojit_import_entries(module) + idx;
  const char *target = (const char *)entry + *entry;
  if ((autojit_import_indirect(module)[idx / 8] >> (idx % 8)) & 1) {
    uint64_t addr;
    memcpy(&addr, target, sizeof(addr));
    return addr;
  }
  return (uint64_t)(uintptr_t)target;
}

#ifdef __cplusplus
}
#endif
