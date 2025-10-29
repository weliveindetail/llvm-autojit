#pragma once

#include "AutoJITConfig.h"
#include "runtime/AutoJITRuntime.h"
#include "llvm/Config/llvm-config.h"

/* Debug logging controlled by AUTOJIT_DEBUG */
extern int __llvm_autojit_debug;
extern int __llvm_autojit_debug_register;

#define DEBUG_LOG(...)                                                         \
  do {                                                                         \
    if (__llvm_autojit_debug)                                                               \
      fprintf(stderr, "[autojit-stub] " __VA_ARGS__);                           \
  } while (0)

#define ERROR_LOG(...) fprintf(stderr, "[autojit-stub] " __VA_ARGS__)
