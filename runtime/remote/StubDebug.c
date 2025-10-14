/*
 * AutoJIT GDB JIT Interface Support - Pure C implementation
 *
 * Implements the GDB JIT interface to allow debuggers to inspect JITed code.
 * This is a minimal reimplementation of
 * llvm/lib/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.cpp
 */

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * GDB JIT Interface structures
 * ============================================================================
 * Keep in sync with gdb/gdb/jit.h
 */

typedef enum {
  JIT_NOACTION = 0,
  JIT_REGISTER_FN,
  JIT_UNREGISTER_FN
} jit_actions_t;

struct jit_code_entry {
  struct jit_code_entry *next_entry;
  struct jit_code_entry *prev_entry;
  const char *symfile_addr;
  uint64_t symfile_size;
};

struct jit_descriptor {
  uint32_t version;
  uint32_t action_flag;
  struct jit_code_entry *relevant_entry;
  struct jit_code_entry *first_entry;
};

/* First version as landed in August 2009 */
#define JIT_DESCRIPTOR_VERSION 1

/* Global descriptor that GDB reads */
__attribute__((used)) struct jit_descriptor __jit_debug_descriptor = {
    JIT_DESCRIPTOR_VERSION, 0, NULL, NULL};

/* Debuggers put a breakpoint in this function */
__attribute__((used, noinline)) void __jit_debug_register_code(void) {
  /* The noinline and the asm prevent calls to this function from being
   * optimized out. */
#if !defined(_MSC_VER)
  __asm__ __volatile__("" ::: "memory");
#endif
}

/* Mutex for thread-safe access to the descriptor */
static pthread_mutex_t jit_debug_lock = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * JIT Code Registration
 * ============================================================================
 */

static void append_jit_debug_descriptor(const char *obj_addr, uint64_t size) {
  struct jit_code_entry *entry = malloc(sizeof(struct jit_code_entry));
  if (!entry)
    return;

  entry->symfile_addr = obj_addr;
  entry->symfile_size = size;
  entry->prev_entry = NULL;

  /* Serialize access to shared data */
  pthread_mutex_lock(&jit_debug_lock);

  /* Insert at head of list */
  struct jit_code_entry *next = __jit_debug_descriptor.first_entry;
  entry->next_entry = next;
  if (next) {
    next->prev_entry = entry;
  }

  __jit_debug_descriptor.first_entry = entry;
  __jit_debug_descriptor.relevant_entry = entry;
  __jit_debug_descriptor.action_flag = JIT_REGISTER_FN;

  pthread_mutex_unlock(&jit_debug_lock);
}

/* ============================================================================
 * SPS Wrapper Function Implementation
 * ============================================================================
 *
 * The wrapper functions receive SPS-encoded arguments:
 * - ExecutorAddrRange (start:8, size:8)
 * - bool (auto_register:1)
 *
 * They must return a CWrapperFunctionResult:
 * - [size:8][data:size] where size=0 for success
 */

typedef struct {
  uint64_t size;
  char *data;
} cwrapper_function_result_t;

static cwrapper_function_result_t make_success_result(void) {
  cwrapper_function_result_t result;
  result.size = 0;
  result.data = NULL;
  return result;
}

static cwrapper_function_result_t make_error_result(const char *error_msg) {
  cwrapper_function_result_t result;
  size_t msg_len = strlen(error_msg);
  result.size = msg_len;
  result.data = malloc(msg_len);
  if (result.data) {
    memcpy(result.data, error_msg, msg_len);
  } else {
    result.size = 0;
  }
  return result;
}

/* Parse SPS-encoded arguments: SPSError(SPSExecutorAddrRange, bool) */
static int parse_register_args(const char *data, uint64_t size,
                               uint64_t *start_addr, uint64_t *range_size,
                               int *auto_register) {
  if (size < 17) /* Need at least 8 + 8 + 1 bytes */
    return -1;

  const uint8_t *ptr = (const uint8_t *)data;

  /* Read ExecutorAddrRange: start address (8 bytes) + size (8 bytes) */
  memcpy(start_addr, ptr, 8);
  ptr += 8;
  memcpy(range_size, ptr, 8);
  ptr += 8;

  /* Read bool: 1 byte (0 or 1) */
  *auto_register = *ptr;

  return 0;
}

/* ============================================================================
 * Exported Wrapper Functions
 * ============================================================================
 */

__attribute__((used)) cwrapper_function_result_t
llvm_orc_registerJITLoaderGDBWrapper(const char *data, uint64_t size) {
  uint64_t start_addr;
  uint64_t range_size;
  int auto_register;

  if (parse_register_args(data, size, &start_addr, &range_size,
                          &auto_register) < 0) {
    return make_error_result("Failed to parse arguments");
  }

  const char *obj_addr = (const char *)(uintptr_t)start_addr;
  append_jit_debug_descriptor(obj_addr, range_size);

  /* Run into the rendezvous breakpoint if requested */
  if (auto_register) {
    __jit_debug_register_code();
  }

  return make_success_result();
}

__attribute__((used)) cwrapper_function_result_t
llvm_orc_registerJITLoaderGDBAllocAction(const char *data, size_t size) {
  /* Same implementation as the wrapper function */
  return llvm_orc_registerJITLoaderGDBWrapper(data, size);
}
