#include "runtime/remote/Stub.h"
#include "runtime/remote/StubSPS.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* ============================================================================
 * SimpleRemoteEPC Wire Protocol (FDSimpleRemoteEPCTransport)
 * ============================================================================
 *
 * Message format: [MsgSize:8][OpCode:8][SeqNo:8][TagAddr:8][ArgBytes:variable]
 *
 * Header is 32 bytes total (4 x uint64_t in little-endian):
 * - MsgSize: Total message size including this header
 * - OpCode: Operation code
 * - SeqNo: Sequence number for matching requests/responses
 * - TagAddr: Function address or tag
 *
 * OpCodes:
 * - 0x00: Setup       - Initial handshake with bootstrap symbols
 * - 0x01: Hangup      - Disconnect
 * - 0x02: Result      - Reply to CallWrapper
 * - 0x03: CallWrapper - RPC call
 */

#define OPCODE_SETUP 0x00
#define OPCODE_HANGUP 0x01
#define OPCODE_RESULT 0x02
#define OPCODE_CALLWRAPPER 0x03

#define FD_MSG_HEADER_SIZE 32

/* Global state */
static int g_daemon_fd = -1;
static pid_t g_daemon_child_pid = -1;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_io_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_next_seqno = 0;

/* Cached function addresses from daemon bootstrap symbols */
static uint64_t g_register_fn_addr = 0;
static uint64_t g_materialize_fn_addr = 0;

/* Debug logging controlled by AUTOJIT_DEBUG */
int __llvm_autojit_debug = 0;
int __llvm_autojit_debug_register = 0;

/* ============================================================================
 * Low-level I/O
 * ============================================================================
 */

static int write_all(const void *buf, size_t count) {
  const char *ptr = (const char *)buf;
  size_t remaining = count;

  while (remaining > 0) {
    ssize_t written = write(g_daemon_fd, ptr, remaining);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      ERROR_LOG("write failed: %s\n", strerror(errno));
      g_daemon_fd = -1;
      return -1;
    }
    ptr += written;
    remaining -= written;
  }
  return 0;
}

static int read_all(void *buf, size_t count) {
  char *ptr = (char *)buf;
  size_t remaining = count;

  while (remaining > 0) {
    ssize_t nread = read(g_daemon_fd, ptr, remaining);
    if (nread < 0) {
      if (errno == EINTR)
        continue;
      ERROR_LOG("read failed: %s\n", strerror(errno));
      g_daemon_fd = -1;
      return -1;
    }
    if (nread == 0) {
      ERROR_LOG("unexpected EOF from daemon\n");
      g_daemon_fd = -1;
      return -1;
    }
    ptr += nread;
    remaining -= nread;
  }
  return 0;
}

/* ============================================================================
 * SimpleRemoteEPC Message Handling
 * ============================================================================
 */

typedef struct {
  uint64_t opcode;
  uint64_t seqno;
  uint64_t tag_addr;
  uint8_t *arg_bytes;
  size_t arg_size;
} epc_message_t;

static int send_epc_message(const epc_message_t *msg) {
  pthread_mutex_lock(&g_io_mutex);

  /* Construct header: [MsgSize:8][OpCode:8][SeqNo:8][TagAddr:8] */
  uint64_t msg_size = FD_MSG_HEADER_SIZE + msg->arg_size;
  uint8_t header[FD_MSG_HEADER_SIZE];

  memcpy(header + 0, &msg_size, 8);
  memcpy(header + 8, &msg->opcode, 8);
  memcpy(header + 16, &msg->seqno, 8);
  memcpy(header + 24, &msg->tag_addr, 8);

  int ret = 0;
  if (write_all(header, FD_MSG_HEADER_SIZE) < 0) {
    ret = -1;
  } else if (msg->arg_size > 0 &&
             write_all(msg->arg_bytes, msg->arg_size) < 0) {
    ret = -1;
  }

  pthread_mutex_unlock(&g_io_mutex);
  return ret;
}

static int recv_epc_message(epc_message_t *msg) {
  pthread_mutex_lock(&g_io_mutex);

  /* Read header: [MsgSize:8][OpCode:8][SeqNo:8][TagAddr:8] */
  uint8_t header[FD_MSG_HEADER_SIZE];
  if (read_all(header, FD_MSG_HEADER_SIZE) < 0) {
    pthread_mutex_unlock(&g_io_mutex);
    return -1;
  }

  uint64_t msg_size;
  memcpy(&msg_size, header + 0, 8);
  memcpy(&msg->opcode, header + 8, 8);
  memcpy(&msg->seqno, header + 16, 8);
  memcpy(&msg->tag_addr, header + 24, 8);

  /* Calculate size of argument bytes */
  if (msg_size < FD_MSG_HEADER_SIZE) {
    ERROR_LOG("Invalid message size: %lu\n", msg_size);
    pthread_mutex_unlock(&g_io_mutex);
    return -1;
  }

  msg->arg_size = msg_size - FD_MSG_HEADER_SIZE;

  /* Read argument bytes if present */
  if (msg->arg_size > 0) {
    msg->arg_bytes = malloc(msg->arg_size);
    if (!msg->arg_bytes) {
      pthread_mutex_unlock(&g_io_mutex);
      return -1;
    }

    if (read_all(msg->arg_bytes, msg->arg_size) < 0) {
      free(msg->arg_bytes);
      pthread_mutex_unlock(&g_io_mutex);
      return -1;
    }
  } else {
    msg->arg_bytes = NULL;
  }

  pthread_mutex_unlock(&g_io_mutex);
  return 0;
}

static void free_epc_message(epc_message_t *msg) {
  free(msg->arg_bytes);
  msg->arg_bytes = NULL;
  msg->arg_size = 0;
}

static uint64_t next_sequence_number(void) {
  return __sync_fetch_and_add(&g_next_seqno, 1);
}

static void count_sequence_number(uint64_t actual) {
  uint64_t expected = next_sequence_number();
  if (actual != expected) {
    ERROR_LOG("Warning: Expected sequence number %lu but got: %lu\n", expected,
              actual);
    if (__llvm_autojit_debug) {
      abort();
    }
  }
}

/* ============================================================================
 * Bootstrap Symbol Parsing
 * ============================================================================
 */

static int parse_setup_message(const epc_message_t *msg) {
  /* Setup message format (SPS encoded):
   * - target_triple: string
   * - page_size: uint64_t
   * - bootstrap_map: map<string, bytes> (we skip this)
   * - bootstrap_symbols: map<string, uint64_t>
   */

  /* Keep sequence numbers in sync bi-directionally */
  count_sequence_number(msg->seqno);

  const uint8_t *ptr = msg->arg_bytes;
  const uint8_t *end = msg->arg_bytes + msg->arg_size;

  /* Skip target triple */
  char *triple;
  uint64_t triple_len;
  if (sps_read_string(&ptr, end, &triple, &triple_len) < 0) {
    ERROR_LOG("Failed to parse target triple\n");
    return -1;
  }
  DEBUG_LOG("Target triple: %s\n", triple);
  free(triple);

  /* Skip page size */
  uint64_t page_size;
  if (sps_read_uint64(&ptr, end, &page_size) < 0) {
    ERROR_LOG("Failed to parse page size\n");
    return -1;
  }
  DEBUG_LOG("Page size: %lu\n", page_size);

  /* Skip bootstrap map (map of byte vectors) */
  uint64_t map_size;
  if (sps_read_uint64(&ptr, end, &map_size) < 0) {
    ERROR_LOG("Failed to parse bootstrap map size\n");
    return -1;
  }

  for (uint64_t i = 0; i < map_size; i++) {
    char *key;
    uint64_t key_len;
    if (sps_read_string(&ptr, end, &key, &key_len) < 0) {
      ERROR_LOG("Failed to parse bootstrap map key\n");
      return -1;
    }
    free(key);

    uint64_t value_size;
    if (sps_read_uint64(&ptr, end, &value_size) < 0) {
      ERROR_LOG("Failed to parse bootstrap map value size\n");
      return -1;
    }

    ptr += value_size; /* Skip the value bytes */
    if (ptr > end) {
      ERROR_LOG("Bootstrap map value out of bounds\n");
      return -1;
    }
  }

  /* Parse bootstrap symbols map */
  uint64_t symbols_size;
  if (sps_read_uint64(&ptr, end, &symbols_size) < 0) {
    ERROR_LOG("Failed to parse bootstrap symbols size\n");
    return -1;
  }

  DEBUG_LOG("Parsing %lu bootstrap symbols\n", symbols_size);

  for (uint64_t i = 0; i < symbols_size; i++) {
    char *name;
    uint64_t name_len;
    if (sps_read_string(&ptr, end, &name, &name_len) < 0) {
      ERROR_LOG("Failed to parse symbol name\n");
      return -1;
    }

    uint64_t addr;
    if (sps_read_uint64(&ptr, end, &addr) < 0) {
      ERROR_LOG("Failed to parse symbol address\n");
      free(name);
      return -1;
    }

    DEBUG_LOG("Bootstrap symbol: %s = 0x%lx\n", name, addr);

    if (strcmp(name, "autojit_rpc_register") == 0) {
      g_register_fn_addr = addr;
    } else if (strcmp(name, "autojit_rpc_materialize") == 0) {
      g_materialize_fn_addr = addr;
    }

    free(name);
  }

  if (g_register_fn_addr == 0 || g_materialize_fn_addr == 0) {
    ERROR_LOG("Failed to find required bootstrap symbols\n");
    return -1;
  }

  DEBUG_LOG("Found register function at 0x%lx\n", g_register_fn_addr);
  DEBUG_LOG("Found materialize function at 0x%lx\n", g_materialize_fn_addr);

  return 0;
}

/* ============================================================================
 * Forward Declarations
 * ============================================================================
 */

/* Message handling functions - defined later in the file */
static int message_loop_until(uint64_t stop_opcode, epc_message_t *stop_msg);

/* EH-frame registration wrappers - defined later in the file */
static ssize_t llvm_orc_registerEHFrameAllocAction(const char *ArgData,
                                                      size_t ArgSize,
                                                      sps_buffer_t *Result);
static ssize_t llvm_orc_deregisterEHFrameAllocAction(const char *ArgData,
                                                        size_t ArgSize,
                                                        sps_buffer_t *Result);

/* ============================================================================
 * Bootstrap Service Implementations (Simplified Stubs)
 * ============================================================================
 */

/* Memory write wrappers - decode SPS and perform writes directly to memory */
static ssize_t stub_mem_write_uint8s_wrapper(const char *ArgData,
                                             size_t ArgSize,
                                             sps_buffer_t *Result) {
  /* Decode SPSSequence<SPSMemoryAccessUInt8Write>
   * Each write is: (ExecutorAddr Addr, uint8_t Value)
   */
  (void)Result; /* Unused */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return -1;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    uint8_t value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return -1;
    if (ptr + 1 > end)
      return -1;
    value = *ptr++;

    *(uint8_t *)addr = value;
  }

  return 0; /* Success, no result data */
}

static ssize_t stub_mem_write_uint16s_wrapper(const char *ArgData,
                                              size_t ArgSize,
                                              sps_buffer_t *Result) {
  (void)Result; /* Unused */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return -1;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    uint16_t value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return -1;
    if (ptr + 2 > end)
      return -1;
    memcpy(&value, ptr, 2);
    ptr += 2;

    *(uint16_t *)addr = value;
  }

  return 0; /* Success, no result data */
}

static ssize_t stub_mem_write_uint32s_wrapper(const char *ArgData,
                                              size_t ArgSize,
                                              sps_buffer_t *Result) {
  (void)Result; /* Unused */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return -1;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    uint32_t value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return -1;
    if (ptr + 4 > end)
      return -1;
    memcpy(&value, ptr, 4);
    ptr += 4;

    *(uint32_t *)addr = value;
  }

  return 0; /* Success, no result data */
}

static ssize_t stub_mem_write_uint64s_wrapper(const char *ArgData,
                                              size_t ArgSize,
                                              sps_buffer_t *Result) {
  (void)Result; /* Unused */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return -1;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr, value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return -1;
    if (sps_read_uint64(&ptr, end, &value) < 0)
      return -1;

    *(uint64_t *)addr = value;
  }

  return 0; /* Success, no result data */
}

static ssize_t stub_mem_write_buffers_wrapper(const char *ArgData,
                                              size_t ArgSize,
                                              sps_buffer_t *Result) {
  /* Decode SPSSequence<SPSMemoryAccessBufferWrite>
   * Each write is: (ExecutorAddr Addr, SPSSequence<uint8_t> Buffer)
   */
  (void)Result; /* Unused */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return -1;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr, buf_size;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return -1;
    if (sps_read_uint64(&ptr, end, &buf_size) < 0)
      return -1;
    if (ptr + buf_size > end)
      return -1;

    memcpy((void *)addr, ptr, buf_size);
    ptr += buf_size;
  }

  return 0; /* Success, no result data */
}

static ssize_t stub_mem_write_pointers_wrapper(const char *ArgData,
                                               size_t ArgSize,
                                               sps_buffer_t *Result) {
  /* Decode SPSSequence<SPSMemoryAccessPointerWrite>
   * Each write is: (ExecutorAddr Addr, ExecutorAddr Value)
   */
  (void)Result; /* Unused */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return -1;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr, value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return -1;
    if (sps_read_uint64(&ptr, end, &value) < 0)
      return -1;

    *(uint64_t *)addr = value;
  }

  return 0; /* Success, no result data */
}

/* Memory manager and dylib manager - minimal stub implementations
 * Real implementations would need proper mmap/mprotect for memory manager
 * and dlopen/dlsym for dylib manager. For now, just provide minimal stubs
 * to satisfy the daemon's bootstrap requirements.
 */

/* Instance pointers for managers */
static int g_mem_mgr_instance = 0;
static int g_dylib_mgr_instance = 0;

/* Dylib manager implementation using dlopen/dlsym */
#include <dlfcn.h>

static ssize_t stub_dylib_open_wrapper(const char *ArgData, size_t ArgSize,
                                       sps_buffer_t *Result) {
  /* Args: (ExecutorAddr Instance, SPSString Path, uint64_t Mode)
   * Returns: SPSExpected<SPSExecutorAddr> - the dylib handle or error
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_dylib_open_wrapper: failed to read instance\n");
    return -1;
  }

  /* Read path string */
  char *path;
  uint64_t path_len;
  if (sps_read_string(&ptr, end, &path, &path_len) < 0) {
    DEBUG_LOG("stub_dylib_open_wrapper: failed to read path\n");
    return -1;
  }

  /* Read mode flags */
  uint64_t mode;
  if (sps_read_uint64(&ptr, end, &mode) < 0) {
    DEBUG_LOG("stub_dylib_open_wrapper: failed to read mode\n");
    free(path);
    return -1;
  }

  DEBUG_LOG("stub_dylib_open_wrapper: path=%s, mode=0x%lx\n", path, mode);

  /* Call dlopen - mode maps to RTLD_* flags */
  int dlopen_mode = RTLD_LAZY; /* Default to lazy binding */
  if (mode & 0x1)
    dlopen_mode = RTLD_NOW; /* Immediate binding if requested */
  if (mode & 0x100)
    dlopen_mode |= RTLD_GLOBAL; /* Make symbols globally available */

  void *handle = dlopen(path, dlopen_mode);
  free(path);

  if (!handle) {
    const char *err = dlerror();
    DEBUG_LOG("stub_dylib_open_wrapper: dlopen failed: %s\n", err);
    return -1;
  }

  DEBUG_LOG("stub_dylib_open_wrapper: dlopen succeeded, handle=0x%lx\n",
            (uint64_t)(uintptr_t)handle);

  /* SPSExpected with success: [has_value:1_byte][value:8_if_has_value] */
  sps_write_uint8(Result, 1);
  sps_write_uint64(Result, (uint64_t)(uintptr_t)handle);
  return 0;
}

static ssize_t stub_dylib_lookup_wrapper(const char *ArgData, size_t ArgSize,
                                         sps_buffer_t *Result) {
  /* Args: (ExecutorAddr Instance, ExecutorAddr Handle,
   * SPSRemoteSymbolLookupSet) Returns:
   * SPSExpected<SPSSequence<SPSExecutorSymbolDef>>
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    return -1;
  }

  /* Read dylib handle */
  uint64_t handle_addr;
  if (sps_read_uint64(&ptr, end, &handle_addr) < 0) {
    return -1;
  }

  void *handle = (void *)(uintptr_t)handle_addr;
  DEBUG_LOG("stub_dylib_lookup_wrapper: handle=0x%lx\n", handle_addr);

  /* Read symbol lookup set - for now just count symbols */
  uint64_t num_symbols;
  if (sps_read_uint64(&ptr, end, &num_symbols) < 0) {
    return -1;
  }

  DEBUG_LOG("stub_dylib_lookup_wrapper: looking up %lu symbols\n", num_symbols);

  /* SPSExpected with success: [has_value:1_byte] */
  sps_write_uint8(Result, 1);

  /* Write sequence size (number of symbols found) */
  sps_write_uint64(Result, num_symbols);

  /* For each symbol, read name and lookup */
  for (uint64_t i = 0; i < num_symbols; i++) {
    char *sym_name;
    uint64_t name_len;
    if (sps_read_string(&ptr, end, &sym_name, &name_len) < 0) {
      return -1;
    }

    /* Read required flag */
    uint8_t required;
    if (ptr >= end) {
      free(sym_name);
      return -1;
    }
    required = *ptr++;

    DEBUG_LOG("  Symbol: %s (required=%d)\n", sym_name, required);

    /* Look up symbol with dlsym */
    void *sym_addr = dlsym(handle, sym_name);
    free(sym_name);

    if (!sym_addr) {
      DEBUG_LOG("    dlsym failed: %s\n", dlerror());
      /* Write null address and flags
       * ExecutorSymbolDef: (ExecutorAddr=0, JITSymbolFlags=(0, 0))
       */
      sps_write_uint64(Result, 0);
      sps_write_uint8(Result, 0);
      sps_write_uint8(Result, 0);
    } else {
      DEBUG_LOG("    Found at: 0x%lx\n", (uint64_t)(uintptr_t)sym_addr);
      /* Write ExecutorSymbolDef: (ExecutorAddr address, JITSymbolFlags flags)
       * JITSymbolFlags is a tuple of (UnderlyingType, TargetFlagsType)
       * Both are typically uint8_t, so we write them as 1-byte values
       */
      sps_write_uint64(Result, (uint64_t)(uintptr_t)sym_addr);
      /* Exported symbol flag and empty target flag */
      uint8_t flag_exported = 1 << 4;
      sps_write_uint8(Result, flag_exported);
      sps_write_uint8(Result, 0);
    }
  }

  return 0;
}

/* Memory manager implementation using mmap/mprotect/munmap
 * This provides proper memory management with executable permissions for JIT code
 */
#include <sys/mman.h>

static ssize_t stub_mem_reserve_wrapper(const char *ArgData, size_t ArgSize,
                                        sps_buffer_t *Result) {
  /* Args: (ExecutorAddr Instance, uint64_t Size)
   * Returns: SPSExpected<SPSExecutorAddr> - allocated memory address or error
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_mem_reserve_wrapper: failed to read instance\n");
    return -1;
  }

  /* Read size */
  uint64_t size;
  if (sps_read_uint64(&ptr, end, &size) < 0) {
    DEBUG_LOG("stub_mem_reserve_wrapper: failed to read size\n");
    return -1;
  }

  DEBUG_LOG("stub_mem_reserve_wrapper: size=%lu\n", size);

  /* Allocate memory with mmap - initially RW, will be made executable in finalize
   * MAP_ANONYMOUS = not backed by a file
   * MAP_PRIVATE = changes are private to this process
   */
  void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    DEBUG_LOG("stub_mem_reserve_wrapper: mmap failed: %s\n", strerror(errno));
    return -1;
  }

  DEBUG_LOG("stub_mem_reserve_wrapper: allocated at 0x%lx\n",
            (uint64_t)(uintptr_t)mem);

  /* SPSExpected with success: [has_value:1_byte][value:8_if_has_value] */
  sps_write_uint8(Result, 1);
  sps_write_uint64(Result, (uint64_t)(uintptr_t)mem);

  return 0; /* Success */
}

static ssize_t stub_mem_finalize_wrapper(const char *ArgData, size_t ArgSize,
                                         sps_buffer_t *Result) {
  /* Args: (ExecutorAddr Instance, SPSFinalizeRequest)
   * Returns: SPSError - empty for success, error message for failure
   *
   * FinalizeRequest format (SPS):
   *   SPSTuple<SPSSequence<SPSSegFinalizeRequest>, SPSSequence<SPSAllocActionCallPair>>
   *
   * SPSSegFinalizeRequest:
   *   SPSTuple<SPSRemoteAllocGroup, SPSExecutorAddr, uint64_t, SPSSequence<char>>
   *   - RemoteAllocGroup: uint8_t with flags (Read=1, Write=2, Exec=4, Finalize=8)
   *   - ExecutorAddr: uint64_t address
   *   - Size: uint64_t
   *   - Content: sequence of bytes (for content writes)
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_mem_finalize_wrapper: failed to read instance\n");
    return -1;
  }

  DEBUG_LOG("stub_mem_finalize_wrapper: processing finalize request\n");

  /* Read number of segments */
  uint64_t num_segments;
  if (sps_read_uint64(&ptr, end, &num_segments) < 0) {
    DEBUG_LOG("stub_mem_finalize_wrapper: failed to read num_segments\n");
    return -1;
  }

  DEBUG_LOG("  Processing %lu segments\n", num_segments);

  /* Process each segment */
  for (uint64_t i = 0; i < num_segments; i++) {
    /* Read RemoteAllocGroup flags (1 byte) */
    if (ptr >= end) {
      DEBUG_LOG("stub_mem_finalize_wrapper: buffer underrun at segment %lu\n", i);
      return -1;
    }
    uint8_t prot_flags = *ptr++;

    /* Read segment address */
    uint64_t addr;
    if (sps_read_uint64(&ptr, end, &addr) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read address\n");
      return -1;
    }

    /* Read segment size */
    uint64_t size;
    if (sps_read_uint64(&ptr, end, &size) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read size\n");
      return -1;
    }

    /* Read content sequence length */
    uint64_t content_len;
    if (sps_read_uint64(&ptr, end, &content_len) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read content_len\n");
      return -1;
    }

    /* Skip content bytes */
    if (ptr + content_len > end) {
      DEBUG_LOG("stub_mem_finalize_wrapper: content out of bounds\n");
      return -1;
    }

    /* If there's content, write it to the segment */
    if (content_len > 0) {
      DEBUG_LOG("  Segment %lu: addr=0x%lx, size=%lu, writing %lu bytes of content\n",
                i, addr, size, content_len);
      memcpy((void *)(uintptr_t)addr, ptr, content_len);
      ptr += content_len;
    } else {
      DEBUG_LOG("  Segment %lu: addr=0x%lx, size=%lu (no content)\n", i, addr, size);
    }

    /* Convert protection flags to mprotect flags
     * RemoteAllocGroup flags: Read=1, Write=2, Exec=4
     */
    int prot = PROT_NONE;
    if (prot_flags & 0x1)
      prot |= PROT_READ;
    if (prot_flags & 0x2)
      prot |= PROT_WRITE;
    if (prot_flags & 0x4)
      prot |= PROT_EXEC;

    DEBUG_LOG("  Applying mprotect: addr=0x%lx, size=%lu, prot=%d (R=%d W=%d X=%d)\n",
              addr, size, prot,
              (prot & PROT_READ) ? 1 : 0,
              (prot & PROT_WRITE) ? 1 : 0,
              (prot & PROT_EXEC) ? 1 : 0);

    /* Apply memory protection */
    if (mprotect((void *)(uintptr_t)addr, size, prot) < 0) {
      DEBUG_LOG("  mprotect failed: %s\n", strerror(errno));
      return -1;
    }
  }

  /* Process allocation actions: SPSSequence<SPSAllocActionCallPair>
   * Each action pair contains:
   *   - Finalize: SPSWrapperFunctionCall (SPSTuple<ExecutorAddr, SPSSequence<char>>)
   *   - Dealloc: SPSWrapperFunctionCall (SPSTuple<ExecutorAddr, SPSSequence<char>>)
   */
  uint64_t num_actions;
  if (sps_read_uint64(&ptr, end, &num_actions) < 0) {
    DEBUG_LOG("stub_mem_finalize_wrapper: failed to read num_actions\n");
    return -1;
  }

  DEBUG_LOG("  Processing %lu allocation actions\n", num_actions);

  /* Execute finalize actions in order */
  for (uint64_t i = 0; i < num_actions; i++) {
    /* Read Finalize WrapperFunctionCall */
    uint64_t finalize_fn_addr;
    if (sps_read_uint64(&ptr, end, &finalize_fn_addr) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read finalize_fn_addr\n");
      return -1;
    }

    uint64_t finalize_arg_size;
    if (sps_read_uint64(&ptr, end, &finalize_arg_size) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read finalize_arg_size\n");
      return -1;
    }

    if (ptr + finalize_arg_size > end) {
      DEBUG_LOG("stub_mem_finalize_wrapper: finalize args out of bounds\n");
      return -1;
    }

    const char *finalize_args = (const char *)ptr;
    ptr += finalize_arg_size;

    /* Read Dealloc WrapperFunctionCall (we skip execution for now) */
    uint64_t dealloc_fn_addr;
    if (sps_read_uint64(&ptr, end, &dealloc_fn_addr) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read dealloc_fn_addr\n");
      return -1;
    }

    uint64_t dealloc_arg_size;
    if (sps_read_uint64(&ptr, end, &dealloc_arg_size) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read dealloc_arg_size\n");
      return -1;
    }

    if (ptr + dealloc_arg_size > end) {
      DEBUG_LOG("stub_mem_finalize_wrapper: dealloc args out of bounds\n");
      return -1;
    }

    ptr += dealloc_arg_size; /* Skip dealloc args */

    /* Execute finalize action if present (non-zero function address) */
    if (finalize_fn_addr != 0) {
      DEBUG_LOG("  Action %lu: calling finalize fn at 0x%lx with %lu bytes args\n",
                i, finalize_fn_addr, finalize_arg_size);

      typedef ssize_t (*WrapperFn)(const char *, size_t, sps_buffer_t *);
      WrapperFn finalize_fn = (WrapperFn)(uintptr_t)finalize_fn_addr;

      sps_buffer_t finalize_result;
      sps_buffer_init(&finalize_result, 64);

      ssize_t ret = finalize_fn(finalize_args, finalize_arg_size, &finalize_result);

      sps_buffer_free(&finalize_result);

      if (ret < 0) {
        DEBUG_LOG("  Action %lu: finalize function failed\n", i);
        /* TODO: Run dealloc actions in reverse order on failure */
        return -1;
      }

      DEBUG_LOG("  Action %lu: finalize function succeeded\n", i);
    } else {
      DEBUG_LOG("  Action %lu: no finalize function (skipped)\n", i);
    }

    /* Note: Dealloc actions should be saved and executed later during
     * stub_mem_deallocate_wrapper, but we don't track them yet.
     */
    if (dealloc_fn_addr != 0) {
      DEBUG_LOG("  Action %lu: dealloc fn at 0x%lx (deferred, not tracked yet)\n",
                i, dealloc_fn_addr);
    }
  }

  /* SPSError [has_error:1_byte] */
  sps_write_uint8(Result, 0);

  return 1; /* Success - SPSError return type (different from SPSExpected) */
}

static ssize_t stub_mem_deallocate_wrapper(const char *ArgData, size_t ArgSize,
                                           sps_buffer_t *Result) {
  /* Args: (ExecutorAddr Instance, SPSSequence<SPSExecutorAddr>)
   * Returns: SPSError - empty for success, error message for failure
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_mem_deallocate_wrapper: failed to read instance\n");
    return -1;
  }

  /* Read sequence of allocation descriptors
   * Each descriptor is actually a struct with address and size
   * For simple implementation, we'll assume each entry is just an address
   * and we need to track sizes separately (or just leak for now)
   */
  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0) {
    DEBUG_LOG("stub_mem_deallocate_wrapper: failed to read count\n");
    return -1;
  }

  DEBUG_LOG("stub_mem_deallocate_wrapper: deallocating %lu addresses\n", count);

  /* For each address, we'd need to munmap with the right size
   * Since we don't track sizes here, we'll just skip unmapping for now
   * This is a memory leak but acceptable for initial implementation
   */
  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    if (sps_read_uint64(&ptr, end, &addr) < 0) {
      DEBUG_LOG("stub_mem_deallocate_wrapper: failed to read address %lu\n", i);
      return -1;
    }

    DEBUG_LOG("  Would munmap address 0x%lx (size unknown, skipping)\n", addr);
    /* TODO: Track allocation sizes to properly munmap(addr, size) */
  }

  /* SPSError [has_error:1_byte] */
  sps_write_uint8(Result, 0);
  return 0;
}

/* ============================================================================
 * JIT Dispatch - handles calls from daemon back to stub
 * ============================================================================
 */

/* Opaque type for dispatch context */
typedef struct {
  int unused;
} __orc_rt_Opaque;

/* Dispatch context - just a dummy for now since we don't expect callbacks yet
 */
static __orc_rt_Opaque __orc_rt_jit_dispatch_ctx_impl = {0};

/* Dispatch function - handles RPC calls from daemon to stub */
static void __orc_rt_jit_dispatch_impl(__orc_rt_Opaque *Ctx, const void *FnTag,
                                       const char *ArgData, size_t ArgSize,
                                       void *ResultPtr) {

  DEBUG_LOG("JIT dispatch called with FnTag=%p, ArgSize=%zu\n", FnTag, ArgSize);

  /* For now, we don't handle any callbacks from daemon to stub.
   * If we need to support platform runtime functions like dlopen/dlsym,
   * we would dispatch based on FnTag here.
   *
   * Return empty result (void return).
   */
  uint8_t *result_bytes = (uint8_t *)ResultPtr;
  *((uint64_t *)result_bytes) = 0; /* Size = 0 means empty/void result */
}

/* ============================================================================
 * Setup Message Sending
 * ============================================================================
 */

enum StdLibFlagOffsets {
  LibcGnu = 0,
  LibcMusl = 1,
  LibStdCxx = 8,
  LibCxx = 9,
};

static uint64_t detect_stdlibs(void) {
  uint64_t result = 0;
  if (dlsym(RTLD_DEFAULT, "gnu_get_libc_version"))
    result |= 1 << LibcGnu;
  if (dlsym(RTLD_DEFAULT, "__musl_libc_version"))
    result |= 1 << LibcMusl;
  if (dlsym(RTLD_DEFAULT, "_ZSt4cout"))
    result |= 1 << LibStdCxx;
  if (dlsym(RTLD_DEFAULT, "_ZNSt3__14coutE"))
    result |= 1 << LibCxx;
  return result;
}

static int send_setup_message(void) {
  /* Setup message format (SPS encoded):
   * - target_triple: string
   * - page_size: uint64_t
   * - stdlibs: uint64_t
   * - bootstrap_map: map<string, bytes>
   * - bootstrap_symbols: map<string, uint64_t>
   */

  sps_buffer_t setup_data;
  sps_buffer_init(&setup_data, 2048);

  /* Get target triple - for now use a simple default */
  const char *triple = "x86_64-unknown-linux-gnu";
  sps_write_string(&setup_data, triple);

  /* Get page size */
  uint64_t page_size = sysconf(_SC_PAGESIZE);
  sps_write_uint64(&setup_data, page_size);

  /* Get stdlibs */
  uint64_t stdlibs = detect_stdlibs();
  sps_write_uint64(&setup_data, stdlibs);

  /* Bootstrap map - empty for now */
  sps_write_uint64(&setup_data, 0);

  /* Bootstrap symbols - populate with all required symbols */
  /* Symbol names from llvm/lib/ExecutionEngine/Orc/Shared/OrcRTBridge.cpp */

  /* Count: 2 dispatch + 6 memory write + 3 dylib mgr + 4 memory mgr + 2 eh-frame = 17 */
  sps_write_uint64(&setup_data, 17);

  /* __llvm_orc_SimpleRemoteEPC_dispatch_ctx - context for RPC calls back to
   * stub */
  sps_write_string(&setup_data, "__llvm_orc_SimpleRemoteEPC_dispatch_ctx");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)&__orc_rt_jit_dispatch_ctx_impl);

  /* __llvm_orc_SimpleRemoteEPC_dispatch_fn - function for RPC calls back to
   * stub */
  sps_write_string(&setup_data, "__llvm_orc_SimpleRemoteEPC_dispatch_fn");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)&__orc_rt_jit_dispatch_impl);

  /* Memory write wrappers */
  sps_write_string(&setup_data,
                   "__llvm_orc_bootstrap_mem_write_uint8s_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_write_uint8s_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_bootstrap_mem_write_uint16s_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_write_uint16s_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_bootstrap_mem_write_uint32s_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_write_uint32s_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_bootstrap_mem_write_uint64s_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_write_uint64s_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_bootstrap_mem_write_buffers_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_write_buffers_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_bootstrap_mem_write_pointers_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_write_pointers_wrapper);

  /* Dylib manager */
  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorDylibManager_Instance");
  sps_write_uint64(&setup_data, (uint64_t)(uintptr_t)&g_dylib_mgr_instance);

  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorDylibManager_open_wrapper");
  sps_write_uint64(&setup_data, (uint64_t)(uintptr_t)stub_dylib_open_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorDylibManager_lookup_wrapper");
  sps_write_uint64(&setup_data, (uint64_t)(uintptr_t)stub_dylib_lookup_wrapper);

  /* Memory manager */
  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorMemoryManager_Instance");
  sps_write_uint64(&setup_data, (uint64_t)(uintptr_t)&g_mem_mgr_instance);

  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorMemoryManager_reserve_wrapper");
  sps_write_uint64(&setup_data, (uint64_t)(uintptr_t)stub_mem_reserve_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorMemoryManager_finalize_wrapper");
  sps_write_uint64(&setup_data, (uint64_t)(uintptr_t)stub_mem_finalize_wrapper);

  sps_write_string(&setup_data,
                   "__llvm_orc_SimpleExecutorMemoryManager_deallocate_wrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)stub_mem_deallocate_wrapper);

  /* EH-frame registration wrappers */
  sps_write_string(&setup_data, "llvm_orc_registerEHFrameAllocAction");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)llvm_orc_registerEHFrameAllocAction);

  sps_write_string(&setup_data, "llvm_orc_deregisterEHFrameAllocAction");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)llvm_orc_deregisterEHFrameAllocAction);

  DEBUG_LOG(
      "Sending Setup message: triple=%s, page_size=%lu, bootstrap_symbols=17\n",
      triple, page_size);

  /* Send Setup message */
  epc_message_t setup_msg = {.opcode = OPCODE_SETUP,
                             .seqno = next_sequence_number(),
                             .tag_addr = 0,
                             .arg_bytes = setup_data.data,
                             .arg_size = setup_data.size};

  int ret = send_epc_message(&setup_msg);
  sps_buffer_free(&setup_data);

  if (ret < 0) {
    ERROR_LOG("Failed to send Setup message\n");
    return -1;
  }

  DEBUG_LOG("Setup message sent successfully\n");
  return 0;
}

/* ============================================================================
 * RPC Call Wrapper
 * ============================================================================
 */

static int call_wrapper_function(uint64_t fn_addr, const uint8_t *data,
                                 size_t args_size, uint8_t **result,
                                 size_t *result_size) {
  /* Send CallWrapper message */
  epc_message_t call_msg = {.opcode = OPCODE_CALLWRAPPER,
                            .seqno = next_sequence_number(),
                            .tag_addr = fn_addr,
                            .arg_bytes = (uint8_t *)data,
                            .arg_size = args_size};

  DEBUG_LOG("Calling wrapper function at 0x%lx with seqno %lu\n", fn_addr,
            call_msg.seqno);

  if (send_epc_message(&call_msg) < 0) {
    ERROR_LOG("Failed to send CallWrapper message\n");
    return -1;
  }

  /* Wait for Result message - use message_loop_until to handle any nested
   * CallWrapper messages from the daemon (e.g., memory reserve requests)
   */
  epc_message_t result_msg;
  if (message_loop_until(OPCODE_RESULT, &result_msg) < 0) {
    ERROR_LOG("Failed to receive Result message\n");
    return -1;
  }

  if (result_msg.seqno != call_msg.seqno) {
    ERROR_LOG("Sequence number mismatch: expected %lu, got %lu\n",
              call_msg.seqno, result_msg.seqno);
    free_epc_message(&result_msg);
    return -1;
  }

  DEBUG_LOG("Received result with seqno %lu, arg_size=%zu\n", result_msg.seqno,
            result_msg.arg_size);

  int ec = 0;
  *result = NULL;

  if (result_msg.arg_bytes != NULL && result_msg.arg_size == 0) {
    /* Out-of-band errors have C-string in bytes and zero in size */
    const char *c_str = (char *)result_msg.arg_bytes;
    *result_size = strlen(c_str);
    ec = -1;
  } else {
    *result_size = result_msg.arg_size;
  }

  if (*result_size > 0) {
    *result = malloc(*result_size);
    if (!*result) {
      free_epc_message(&result_msg);
      *result_size = 0;
      return -1;
    }
  }

  if (*result) {
    memcpy(*result, result_msg.arg_bytes, *result_size);
  }

  free_epc_message(&result_msg);
  return ec;
}

/* ============================================================================
 * Message Handling
 * ============================================================================
 */

/* Handle CallWrapper message - find and invoke the wrapper function */
static int handle_callwrapper_message(const epc_message_t *msg) {
  /* tag_addr contains the function pointer to call */
  typedef ssize_t (*WrapperFn)(const char *, size_t, sps_buffer_t *);
  WrapperFn fn = (WrapperFn)(uintptr_t)msg->tag_addr;

  DEBUG_LOG("Handling CallWrapper: fn=0x%lx, seqno=%lu, arg_size=%zu\n",
            msg->tag_addr, msg->seqno, msg->arg_size);

  /* Keep sequence numbers in sync bi-directionally */
  count_sequence_number(msg->seqno);

  /* Initialize result buffer - wrapper functions write result data here
   * Wrappers that return data will write starting at offset 9 (leaving space
   * for size + flag)
   */
  sps_buffer_t result_buf;
  sps_buffer_init(&result_buf, 256);

  /* Call the wrapper function
   * Returns: -1 for error, 0 for SPSExpected success, 1 for SPSError success
   */
  ssize_t ret = fn((const char *)msg->arg_bytes, msg->arg_size, &result_buf);

  /* TODO: Distinguish SPSExpected/SPSError */
  if (ret < 0) {
    ERROR_LOG("Wrapper function returned error\n");
    sps_buffer_free(&result_buf);
    /* Send empty result on error */
    epc_message_t result_msg = {.opcode = OPCODE_RESULT,
                                .seqno = msg->seqno,
                                .tag_addr = 0,
                                .arg_bytes = NULL,
                                .arg_size = 0};
    if (send_epc_message(&result_msg) < 0) {
      ERROR_LOG("Failed to send Result message\n");
      return -1;
    }
    return 0;
  }

  /* Send Result message with the result data */
  epc_message_t result_msg = {.opcode = OPCODE_RESULT,
                              .seqno = msg->seqno,
                              .tag_addr = 0,
                              .arg_bytes = result_buf.data,
                              .arg_size = result_buf.size};

  if (send_epc_message(&result_msg) < 0) {
    sps_buffer_free(&result_buf);
    ERROR_LOG("Failed to send Result message\n");
    return -1;
  }

  DEBUG_LOG("Sent Result for seqno=%lu, result_size=%zu\n", msg->seqno,
            result_buf.size);
  sps_buffer_free(&result_buf);
  return 0;
}

/* Message loop - process messages until we receive a specific stop opcode
 * stop_opcode: The opcode that causes the loop to exit (e.g., OPCODE_SETUP or
 * OPCODE_HANGUP) Returns: 0 on success (when stop_opcode is received), -1 on
 * error On success, the stop message is left in *stop_msg for the caller to
 * process
 */
static int message_loop_until(uint64_t stop_opcode, epc_message_t *stop_msg) {
  DEBUG_LOG("Entering message loop, waiting for opcode 0x%02lx\n", stop_opcode);

  while (1) {
    epc_message_t msg;
    if (recv_epc_message(&msg) < 0) {
      ERROR_LOG("Failed to receive message in message loop\n");
      return -1;
    }

    DEBUG_LOG("Received message: opcode=0x%02lx, seqno=%lu\n", msg.opcode,
              msg.seqno);

    if (msg.opcode == stop_opcode) {
      /* Found the stop message - return it to caller */
      *stop_msg = msg;
      DEBUG_LOG("Received stop opcode 0x%02lx, exiting message loop\n",
                stop_opcode);
      return 0;
    }

    if (msg.opcode == OPCODE_CALLWRAPPER) {
      /* Handle RPC call from daemon */
      if (handle_callwrapper_message(&msg) < 0) {
        ERROR_LOG("Failed to handle CallWrapper message\n");
        free_epc_message(&msg);
        return -1;
      }
      free_epc_message(&msg);
      /* Continue loop */

    } else if (msg.opcode == OPCODE_HANGUP) {
      /* Sporadic daemon disconnect */
      ERROR_LOG("Daemon sent unexpected Hangup\n");
      free_epc_message(&msg);
      close(g_daemon_fd);
      g_daemon_fd = -1;
      return -1;

    } else {
      ERROR_LOG("Unexpected message opcode 0x%02lx in message loop\n",
                msg.opcode);
      free_epc_message(&msg);
      return -1;
    }
  }
}

/* ============================================================================
 * Daemon Initialization
 * ============================================================================
 */

static void to_lowercase(char *str) {
  for (; *str; ++str)
    *str = tolower(*str);
}

int check_range_min_max(uint64_t s, uint64_t e, uint64_t min, uint64_t max) {
  if (s > e)
    return 0;
  if (e - s < min)
    return 0;
  if (e - s > max)
    return 0;
  return 1;
}

static int checkenv(const char *var) {
  char *envvar = getenv(var);
  if (!envvar)
    return 0;
  to_lowercase(envvar);
  const char *true_values[] = {"1", "on", "true", "yes"};
  for (int i = 0; i < 4; i++)
    if (strcmp(envvar, true_values[i]) == 0)
      return 1;
  return 0;
}

static void clean_shutdown(void) {
  DEBUG_LOG("Run synchronous shutdown process\n");
  epc_message_t hangup_msg;
  if (message_loop_until(OPCODE_HANGUP, &hangup_msg) == 0) {
    ERROR_LOG("Daemon sent synchronous Hangup\n");
    free_epc_message(&hangup_msg);
  } else {
    ERROR_LOG("Failed to receive Hangup message from daemon\n");
  }
}

static int waitpid_timeout(pid_t pid, int *status, int timeout_ms) {
  int interval_ms = 8; // check after 8, 16, 32, etc.
  const int interval_max = timeout_ms >> 1;
  while (interval_ms < interval_max) {
    pid_t ret = waitpid(pid, status, WNOHANG);
    if (ret == -1)
      return -1;
    if (ret == pid)
      return 0;
    usleep(interval_ms * 1000);
    interval_ms <<= 1;
  }
  return -1;
}

static int shutdown_child_process(void) {
  if (waitpid_timeout(g_daemon_child_pid, NULL, 256) == 0)
    return 0;
  kill(g_daemon_child_pid, SIGTERM);
  if (waitpid(g_daemon_child_pid, NULL, 0) == 0)
    return 0;
  return -1;
}

static void cleanup_daemon(void) {
  if (g_daemon_fd >= 0) {
    uint8_t full_shutdown_request = 0;
    epc_message_t hangup = {.opcode = OPCODE_HANGUP,
                            .seqno = 0,
                            .tag_addr = 0,
                            .arg_bytes = &full_shutdown_request,
                            .arg_size = 1};

    /* Run full OrcJIT shutdown only if requested explicitly */
    if (checkenv("AUTOJITD_FULL_SHUTDOWN")) {
      DEBUG_LOG("Request full synchronous shutdown from daemon\n");
      full_shutdown_request = 1;
      send_epc_message(&hangup);
      clean_shutdown();
    } else {
      DEBUG_LOG("Send asynchronous hangup to daemon\n");
      send_epc_message(&hangup);
    }
  }

  /* If the daemon runs in a child process, make sure it did shut down */
  if (g_daemon_child_pid > 0) {
    if (shutdown_child_process() < 0) {
      errno = ETIMEDOUT;
      perror("autojitd child process shutdown timed out");
    }
    g_daemon_child_pid = -1;
  }

  if (g_daemon_fd >= 0) {
    close(g_daemon_fd);
    g_daemon_fd = -1;
  }
}

/* Get the socket path for autojitd
 * Returns a pointer to a static buffer containing the socket path.
 * Priority: AUTOJIT_SOCKET_PATH env var, then $XDG_RUNTIME_DIR/autojitd.sock,
 * then /tmp/autojitd-$UID.sock
 */
static const char *get_daemon_socket_path(void) {
  static char socket_path[256];
  const char *env_path = getenv("AUTOJIT_SOCKET_PATH");

  if (env_path) {
    snprintf(socket_path, sizeof(socket_path), "%s", env_path);
    return socket_path;
  }

  const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
  if (runtime_dir) {
    snprintf(socket_path, sizeof(socket_path), "%s/autojitd.sock", runtime_dir);
    return socket_path;
  }

  snprintf(socket_path, sizeof(socket_path), "/tmp/autojitd-%d.sock", getuid());
  return socket_path;
}

/* Try to connect to an existing autojitd process
 * Returns: file descriptor on success, -1 on failure
 */
static int connect_to_existing_daemon(void) {
  const char *socket_path = get_daemon_socket_path();

  DEBUG_LOG("Attempting to connect to existing daemon at %s\n", socket_path);

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    DEBUG_LOG("Failed to create socket: %s\n", strerror(errno));
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    DEBUG_LOG("Failed to connect to daemon socket: %s\n", strerror(errno));
    close(fd);
    return -1;
  }

  DEBUG_LOG("Successfully connected to daemon\n");
  return fd;
}

static void initialize_daemon(void) {
  __llvm_autojit_debug = checkenv("AUTOJIT_DEBUG");
  DEBUG_LOG("Initializing daemon\n");

  /* First, try to connect to an existing daemon */
  int daemon_fd = -1;
  if (!checkenv("AUTOJITD_FORCE_SPAWN"))
    daemon_fd = connect_to_existing_daemon();

  if (checkenv("AUTOJITD_FORCE_DAEMON") && daemon_fd < 0) {
    if (checkenv("AUTOJITD_FORCE_SPAWN")) {
      ERROR_LOG("connecting to daemon failed: AUTOJITD_FORCE_SPAWN and "
                "AUTOJITD_FORCE_DAEMON are mutually exclusive. One must be "
                "disabled in host environment.\n");
    } else {
      ERROR_LOG("connecting to daemon failed: %s\n", strerror(errno));
    }
    abort();
  }

  if (daemon_fd >= 0) {
    /* Connected to daemon, no child process to track */
    g_daemon_fd = daemon_fd;
    g_daemon_child_pid = -1;
  } else {
    /* No daemon found, spawn our own */
    const char *daemon_path = getenv("AUTOJIT_DAEMON_PATH");
    if (!daemon_path)
      daemon_path = "autojitd";
    DEBUG_LOG("No daemon found, spawning autojitd in child-process: %s\n",
              daemon_path);

    /* Create socketpair for bidirectional communication */
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
      ERROR_LOG("socketpair failed: %s\n", strerror(errno));
      abort();
    }

    /* Fork daemon process */
    pid_t pid = fork();
    if (pid < 0) {
      ERROR_LOG("fork failed: %s\n", strerror(errno));
      abort();
    }

    if (pid == 0) {
      /* Child process - exec daemon */
      close(fds[1]);

      /* Redirect stdin/stdout to socket */
      dup2(fds[0], STDIN_FILENO);
      dup2(fds[0], STDOUT_FILENO);
      if (fds[0] > STDERR_FILENO)
        close(fds[0]);

      /* Run autojitd executable */
      execl(daemon_path, "autojitd", "--stdio", NULL);
      fprintf(stderr, "autojit-stub: failed to exec daemon '%s': %s\n",
              daemon_path, strerror(errno));
      _exit(1);
    }

    /* Parent process */
    close(fds[0]);
    g_daemon_fd = fds[1];
    g_daemon_child_pid = pid;

    DEBUG_LOG("Daemon started with pid %d\n", g_daemon_child_pid);
  }

  if (checkenv("AUTOJIT_WAIT_FOR_DEBUGGER")) {
    printf("Waiting for debugger. Press ENTER to continue...");
    fflush(stdout);
    int c;
    while ((c = getchar()) != '\n' && c != EOF) ;
  }

  /* Send Setup message to daemon */
  if (send_setup_message() < 0) {
    ERROR_LOG("Failed to send Setup message to daemon\n");
    cleanup_daemon();
    abort();
  }

  /* Message loop: process messages until we receive Setup message from daemon
   * The daemon may send CallWrapper messages during initialization before
   * sending its Setup message. message_loop_until will handle these.
   */
  epc_message_t setup_msg;
  if (message_loop_until(OPCODE_SETUP, &setup_msg) < 0) {
    ERROR_LOG("Failed to receive Setup message from daemon\n");
    cleanup_daemon();
    abort();
  }

  DEBUG_LOG("Received Setup message\n");

  /* Parse bootstrap symbols */
  if (parse_setup_message(&setup_msg) < 0) {
    ERROR_LOG("Failed to parse Setup message\n");
    free_epc_message(&setup_msg);
    cleanup_daemon();
    abort();
  }

  free_epc_message(&setup_msg);

  DEBUG_LOG("Daemon initialization complete\n");

  /* Register cleanup handler */
  atexit(cleanup_daemon);
}

/* ============================================================================
 * EH-Frame Registration Wrappers
 * ============================================================================
 */

/* External declarations for libunwind/libgcc eh-frame functions */
extern void __register_frame(const void *);
extern void __deregister_frame(const void *);

/* Wrapper for registering EH frames - called by daemon via RPC
 * Args: SPSExecutorAddrRange (Start:uint64_t, End:uint64_t)
 * Returns: SPSError (bool HasError, optional error string)
 */
static ssize_t llvm_orc_registerEHFrameAllocAction(const char *ArgData,
                                                      size_t ArgSize,
                                                      sps_buffer_t *Result) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read ExecutorAddrRange: (Start, End) */
  uint64_t start_addr, end_addr;
  if (sps_read_uint64(&ptr, end, &start_addr) < 0 ||
      sps_read_uint64(&ptr, end, &end_addr) < 0) {
    DEBUG_LOG("llvm_orc_registerEHFrameAllocAction: failed to read args\n");
    return -1;
  }

  /* .eh_frame section size is between 8 bytes and 1 GB */
  if (check_range_min_max(start_addr, end_addr, 8, 1 << 30) == 0) {
    ERROR_LOG("Warning: bogus .eh_frame section "
              "[0x%lx -- 0x%lx]\n", start_addr, end_addr);
  }

  DEBUG_LOG("Registering EH frame section at 0x%lx\n", start_addr);

  /* Call __register_frame with the start address
   * Note: libgcc expects a pointer to the start of the .eh_frame section.
   * libunwind might require walking the section and registering each FDE,
   * but for now we assume libgcc behavior (simpler and more common).
   */
  __register_frame((const void *)(uintptr_t)start_addr);

  /* SPSError [has_error:1_byte] */
  sps_write_uint8(Result, 0);
  return 0;
}

/* Wrapper for deregistering EH frames - called by daemon via RPC
 * Args: SPSExecutorAddrRange (Start:uint64_t, End:uint64_t)
 * Returns: SPSError (bool HasError, optional error string)
 */
static ssize_t llvm_orc_deregisterEHFrameAllocAction(const char *ArgData,
                                                        size_t ArgSize,
                                                        sps_buffer_t *Result) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read ExecutorAddrRange: (Start, Size) */
  uint64_t start_addr, end_addr;
  if (sps_read_uint64(&ptr, end, &start_addr) < 0 ||
      sps_read_uint64(&ptr, end, &end_addr) < 0) {
    DEBUG_LOG("llvm_orc_deregisterEHFrameAllocAction: failed to read args\n");
    return -1;
  }

  /* .eh_frame section size is between 8 bytes and 1 GB */
  if (check_range_min_max(start_addr, end_addr, 8, 1 << 30) == 0) {
    ERROR_LOG("Warning: bogus .eh_frame section "
              "[0x%lx -- 0x%lx]\n", start_addr, end_addr);
  }

  DEBUG_LOG("Deregistering EH frame section at 0x%lx\n", start_addr);

  /* Call __deregister_frame with the start address */
  __deregister_frame((const void *)(uintptr_t)start_addr);

  /* SPSError [has_error:1_byte] */
  sps_write_uint8(Result, 0);
  return 0;
}

/* ============================================================================
 * Public API Implementation
 * ============================================================================
 */

void __llvm_autojit_register(const char *FilePath) {
  if (!FilePath) {
    ERROR_LOG("invalid FilePath parameter\n");
    return;
  }

  /* Ensure daemon is initialized */
  pthread_once(&g_init_once, initialize_daemon);

  DEBUG_LOG("Registering module: %s\n", FilePath);

  /* Encode arguments: SPSArgList<SPSString> */
  sps_buffer_t args;
  sps_buffer_init(&args, 256);
  sps_write_string(&args, FilePath);
  DEBUG_LOG("Encoded %zu bytes for RPC call\n", args.size);

  /* Call RPC function */
  uint8_t *result;
  size_t result_size;

  if (call_wrapper_function(g_register_fn_addr, args.data, args.size, &result,
                            &result_size) < 0) {
    if (result_size) {
      ERROR_LOG("autojit_rpc_register failed: %s\n", result);
    } else {
      ERROR_LOG("autojit_rpc_register failed\n");
    }
    sps_buffer_free(&args);
    abort();
  }

  sps_buffer_free(&args);
  free(result);

  DEBUG_LOG("Module registered successfully\n");
}

void __jit_debug_register_code(void);

void __llvm_autojit_materialize(void **GuidInPtrOut) {
  if (!GuidInPtrOut || *GuidInPtrOut == NULL) {
    ERROR_LOG("invalid parameters\n");
    abort();
  }

  /* Ensure daemon is initialized */
  pthread_once(&g_init_once, initialize_daemon);

  uint64_t guid = (uint64_t)(uintptr_t)(*GuidInPtrOut);
  DEBUG_LOG("Requesting function: __autojit_fn_%lu\n", guid);

  /* Encode arguments: SPSArgList<uint64_t> */
  sps_buffer_t args;
  sps_buffer_init(&args, 8);
  sps_write_uint64(&args, guid);

  /* Call RPC function */
  uint8_t *result;
  size_t result_size;
  if (call_wrapper_function(g_materialize_fn_addr, args.data, args.size,
                            &result, &result_size) < 0) {
    if (result_size) {
      ERROR_LOG("autojit_rpc_materialize failed: %s\n", result);
    } else {
      ERROR_LOG("autojit_rpc_materialize failed\n");
    }
    sps_buffer_free(&args);
    abort();
  }

  sps_buffer_free(&args);

  /* Decode result: SPSArgList<uint64_t> */
  if (result_size != 8) {
    ERROR_LOG("Invalid result size: expected 8, got %zu\n", result_size);
    for (size_t i = 0; i < result_size; i += 1) {
      fprintf(stderr, "%02x ", *(result + i));
    }
    fprintf(stderr, "\n");
    free(result);
    abort();
  }

  uint64_t func_addr;
  memcpy(&func_addr, result, 8);
  free(result);

  DEBUG_LOG("Materialized __autojit_fn_%lu at address 0x%016lx\n", guid,
            func_addr);

  if (__sync_lock_test_and_set(&__llvm_autojit_debug_register, 0)) {
    __jit_debug_register_code();
  }

  /* Update pointer with returned address */
  *GuidInPtrOut = (void *)(uintptr_t)func_addr;
}
