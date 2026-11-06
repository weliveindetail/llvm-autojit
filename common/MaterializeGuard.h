#pragma once

/* Materialization must be invisible to the program. It does file I/O and memory
 * mapping, which change errno, and code often calls one of its own functions
 * before it reads errno. A signal on the same thread could run a handler that
 * re-enters the JIT in the middle of loading a module, so handlers wait until
 * we are done. This must stay valid C, because the stub uses it as well. */

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

typedef struct {
  int saved_errno;
  sigset_t saved_mask;
} autojit_materialize_guard_t;

static inline void
autojit_materialize_guard_enter(autojit_materialize_guard_t *guard) {
  sigset_t all;
  guard->saved_errno = errno;
  sigfillset(&all);
  pthread_sigmask(SIG_SETMASK, &all, &guard->saved_mask);
}

static inline void
autojit_materialize_guard_leave(const autojit_materialize_guard_t *guard) {
  pthread_sigmask(SIG_SETMASK, &guard->saved_mask, NULL);
  errno = guard->saved_errno;
}

/* JITed code refers to the image of its lazy module, so that must never unload.
 * dlclose() has no effect on it afterwards. */
static inline void autojit_pin_image(const void *module) {
  Dl_info info;
  if (dladdr(module, &info) && info.dli_fname)
    dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_NODELETE);
}
