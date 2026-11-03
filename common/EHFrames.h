#pragma once

/* Registration of EH frames of JITed code with the unwinder of the program.
 *
 * The runtime must not decide at build-time which unwinder to use: programs
 * use libgcc (e.g. with libstdc++) or LLVM's libunwind (e.g. with libc++) and
 * their APIs behave differently. We find the library that provides the
 * program's _Unwind_RaiseException and use its registration functions:
 *
 * - libunwind with __unw_add_dynamic_eh_frame_section(): pass the section
 * - libunwind without it: pass each FDE to __register_frame()
 * - libgcc: pass the section to __register_frame()
 *
 * The ORC runtime does the same with weak references (elfnix_platform.cpp).
 * We look up symbols at run-time, because the in-process runtime is a shared
 * library with its own private unwinder. The format must be readable from C,
 * because the static stub is pure C.
 */

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*autojit_eh_frame_fn_t)(const void *);

typedef struct {
  /* The unwinder takes the entire .eh_frame section */
  autojit_eh_frame_fn_t add_section;
  autojit_eh_frame_fn_t remove_section;
  /* The unwinder takes individual FDEs */
  autojit_eh_frame_fn_t add_fde;
  autojit_eh_frame_fn_t remove_fde;
  /* Path of the library that provides the unwinder, for diagnostics */
  const char *unwinder;
} autojit_eh_frame_registrar_t;

/* Returns 0 if we found the program's unwinder */
static inline int
autojit_find_eh_frame_registrar(autojit_eh_frame_registrar_t *registrar) {
  memset(registrar, 0, sizeof(*registrar));

  void *raise = dlsym(RTLD_DEFAULT, "_Unwind_RaiseException");
  Dl_info info;
  if (!raise || !dladdr(raise, &info))
    return -1;

  /* Look up the functions in the same library. If it's not a shared library,
   * e.g. a static unwinder exported from the executable, the global scope is
   * the best we can do. */
  void *handle =
      info.dli_fname ? dlopen(info.dli_fname, RTLD_LAZY | RTLD_NOLOAD) : NULL;
  void *scope = handle ? handle : RTLD_DEFAULT;
  registrar->unwinder = info.dli_fname;

  void *add = dlsym(scope, "__unw_add_dynamic_eh_frame_section");
  void *remove = dlsym(scope, "__unw_remove_dynamic_eh_frame_section");
  void *reg = dlsym(scope, "__register_frame");
  void *dereg = dlsym(scope, "__deregister_frame");
  int is_libunwind = dlsym(scope, "__unw_add_dynamic_fde") != NULL;

  if (add && remove) {
    registrar->add_section = (autojit_eh_frame_fn_t)add;
    registrar->remove_section = (autojit_eh_frame_fn_t)remove;
  } else if (reg && dereg && is_libunwind) {
    registrar->add_fde = (autojit_eh_frame_fn_t)reg;
    registrar->remove_fde = (autojit_eh_frame_fn_t)dereg;
  } else if (reg && dereg) {
    registrar->add_section = (autojit_eh_frame_fn_t)reg;
    registrar->remove_section = (autojit_eh_frame_fn_t)dereg;
  }

  /* The library stays loaded: the program uses it */
  if (handle)
    dlclose(handle);
  return registrar->add_section || registrar->add_fde ? 0 : -1;
}

/* Pass each FDE in the section to the given function. Mirrors
 * walkLibunwindEHFrameSection() in LLVM's RegisterEHFrames.cpp. */
static inline void autojit_for_each_fde(const char *section, size_t size,
                                        autojit_eh_frame_fn_t fn) {
  const char *record = section;
  const char *end = section + size;
  while (record < end) {
    uint32_t length32;
    memcpy(&length32, record, sizeof(length32));
    if (length32 == 0)
      break;
    uint64_t length = length32;
    const char *id_field = record + 4;
    if (length32 == 0xffffffff) {
      memcpy(&length, record + 4, sizeof(length));
      id_field = record + 12;
      length += 12;
    } else {
      length += 4;
    }
    uint32_t cie_offset;
    memcpy(&cie_offset, id_field, sizeof(cie_offset));
    if (cie_offset != 0)
      fn(record);
    record += length;
  }
}

static inline void
autojit_register_eh_frames(const autojit_eh_frame_registrar_t *registrar,
                           const void *section, size_t size) {
  if (registrar->add_section)
    registrar->add_section(section);
  else if (registrar->add_fde)
    autojit_for_each_fde((const char *)section, size, registrar->add_fde);
}

static inline void
autojit_deregister_eh_frames(const autojit_eh_frame_registrar_t *registrar,
                             const void *section, size_t size) {
  if (registrar->remove_section)
    registrar->remove_section(section);
  else if (registrar->remove_fde)
    autojit_for_each_fde((const char *)section, size, registrar->remove_fde);
}

#ifdef __cplusplus
}
#endif
