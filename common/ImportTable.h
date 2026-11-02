#pragma once

/* Import table that the plugin emits into each static object. It lists the
 * addresses of all symbols that the lazy module imports from the host process.
 * The runtime derives the matching names from the lazy module itself (see
 * Imports.h), so the binary doesn't need to store them.
 *
 * Layout:
 *   header
 *   int32_t entries[num_entries]     offset from the entry to its target
 *   uint8_t indirect[(num_entries + 7) / 8]
 *
 * Direct entries point to the symbol itself. Indirect entries point to a slot
 * that holds the symbol's address, usually a GOT entry. The format must be
 * readable from C, because the static stub is pure C.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define AUTOJIT_IMPORT_TABLE_VERSION 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t version;
  uint32_t num_entries;
  /* Hash of the import names in order, to detect stale lazy modules */
  uint64_t hash;
} autojit_import_table_t;

static inline const int32_t *
autojit_import_entries(const autojit_import_table_t *table) {
  return (const int32_t *)(table + 1);
}

static inline uint64_t
autojit_import_address(const autojit_import_table_t *table, uint32_t idx) {
  const int32_t *entry = autojit_import_entries(table) + idx;
  const uint8_t *indirect =
      (const uint8_t *)(autojit_import_entries(table) + table->num_entries);
  const char *target = (const char *)entry + *entry;
  if ((indirect[idx / 8] >> (idx % 8)) & 1) {
    uint64_t addr;
    memcpy(&addr, target, sizeof(addr));
    return addr;
  }
  return (uint64_t)(uintptr_t)target;
}

#ifdef __cplusplus
}
#endif
