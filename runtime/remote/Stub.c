#include "runtime/AutoJITRuntime.h"

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
static pid_t g_daemon_pid = -1;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_io_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_next_seqno = 1;

/* Cached function addresses from daemon bootstrap symbols */
static uint64_t g_register_fn_addr = 0;
static uint64_t g_materialize_fn_addr = 0;

/* Debug logging controlled by AUTOJIT_DEBUG */
static int g_debug = 0;

#define DEBUG_LOG(...)                                                         \
  do {                                                                         \
    if (g_debug)                                                               \
      fprintf(stderr, "autojit-stub: " __VA_ARGS__);                           \
  } while (0)

#define ERROR_LOG(...) fprintf(stderr, "autojit-stub: " __VA_ARGS__)

/* ============================================================================
 * Low-level I/O
 * ============================================================================
 */

static int write_all(int fd, const void *buf, size_t count) {
  const char *ptr = (const char *)buf;
  size_t remaining = count;

  while (remaining > 0) {
    ssize_t written = write(fd, ptr, remaining);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      ERROR_LOG("write failed: %s\n", strerror(errno));
      return -1;
    }
    ptr += written;
    remaining -= written;
  }
  return 0;
}

static int read_all(int fd, void *buf, size_t count) {
  char *ptr = (char *)buf;
  size_t remaining = count;

  while (remaining > 0) {
    ssize_t nread = read(fd, ptr, remaining);
    if (nread < 0) {
      if (errno == EINTR)
        continue;
      ERROR_LOG("read failed: %s\n", strerror(errno));
      return -1;
    }
    if (nread == 0) {
      ERROR_LOG("unexpected EOF from daemon\n");
      return -1;
    }
    ptr += nread;
    remaining -= nread;
  }
  return 0;
}

/* ============================================================================
 * SPS (Simple Packed Serialization) Encoding/Decoding
 * ============================================================================
 *
 * We only implement what we need:
 * - uint64_t (8 bytes, native endian)
 * - string (uint64_t length + bytes)
 * - WrapperFunctionResult wrapper (uint64_t size + data)
 */

typedef struct {
  uint8_t *data;
  size_t size;
  size_t capacity;
} sps_buffer_t;

static void sps_buffer_init(sps_buffer_t *buf, size_t capacity) {
  buf->data = malloc(capacity);
  buf->size = 0;
  buf->capacity = capacity;
}

static void sps_buffer_free(sps_buffer_t *buf) {
  free(buf->data);
  buf->data = NULL;
  buf->size = 0;
  buf->capacity = 0;
}

static void sps_write_uint64(sps_buffer_t *buf, uint64_t value) {
  if (buf->size + 8 > buf->capacity) {
    buf->capacity *= 2;
    buf->data = realloc(buf->data, buf->capacity);
  }
  memcpy(buf->data + buf->size, &value, 8);
  buf->size += 8;
}

static void sps_write_string(sps_buffer_t *buf, const char *str) {
  uint64_t len = strlen(str);
  sps_write_uint64(buf, len);

  if (buf->size + len > buf->capacity) {
    buf->capacity = buf->size + len + 256;
    buf->data = realloc(buf->data, buf->capacity);
  }
  memcpy(buf->data + buf->size, str, len);
  buf->size += len;
}

static int sps_read_uint64(const uint8_t **ptr, const uint8_t *end,
                           uint64_t *value) {
  if (*ptr + 8 > end) {
    ERROR_LOG("SPS: buffer underrun reading uint64\n");
    return -1;
  }
  memcpy(value, *ptr, 8);
  *ptr += 8;
  return 0;
}

static int sps_read_string(const uint8_t **ptr, const uint8_t *end, char **str,
                           uint64_t *len) {
  if (sps_read_uint64(ptr, end, len) < 0)
    return -1;

  if (*ptr + *len > end) {
    ERROR_LOG("SPS: buffer underrun reading string\n");
    return -1;
  }

  *str = malloc(*len + 1);
  if (!*str)
    return -1;

  memcpy(*str, *ptr, *len);
  (*str)[*len] = '\0';
  *ptr += *len;
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

static int send_epc_message(int fd, const epc_message_t *msg) {
  pthread_mutex_lock(&g_io_mutex);

  /* Construct header: [MsgSize:8][OpCode:8][SeqNo:8][TagAddr:8] */
  uint64_t msg_size = FD_MSG_HEADER_SIZE + msg->arg_size;
  uint8_t header[FD_MSG_HEADER_SIZE];

  memcpy(header + 0, &msg_size, 8);
  memcpy(header + 8, &msg->opcode, 8);
  memcpy(header + 16, &msg->seqno, 8);
  memcpy(header + 24, &msg->tag_addr, 8);

  int ret = 0;
  if (write_all(fd, header, FD_MSG_HEADER_SIZE) < 0) {
    ret = -1;
  } else if (msg->arg_size > 0 &&
             write_all(fd, msg->arg_bytes, msg->arg_size) < 0) {
    ret = -1;
  }

  pthread_mutex_unlock(&g_io_mutex);
  return ret;
}

static int recv_epc_message(int fd, epc_message_t *msg) {
  pthread_mutex_lock(&g_io_mutex);

  /* Read header: [MsgSize:8][OpCode:8][SeqNo:8][TagAddr:8] */
  uint8_t header[FD_MSG_HEADER_SIZE];
  if (read_all(fd, header, FD_MSG_HEADER_SIZE) < 0) {
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

    if (read_all(fd, msg->arg_bytes, msg->arg_size) < 0) {
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
static int message_loop_until(int fd, uint64_t stop_opcode,
                              epc_message_t *stop_msg);

/* EH-frame registration wrappers - defined later in the file */
static void llvm_orc_registerEHFrameSectionWrapper(const char *ArgData,
                                                    size_t ArgSize,
                                                    uint8_t *ResultPtr);
static void llvm_orc_deregisterEHFrameSectionWrapper(const char *ArgData,
                                                      size_t ArgSize,
                                                      uint8_t *ResultPtr);

/* ============================================================================
 * Bootstrap Service Implementations (Simplified Stubs)
 * ============================================================================
 */

/* Memory write wrappers - decode SPS and perform writes directly to memory */
static void stub_mem_write_uint8s_wrapper(const char *ArgData, size_t ArgSize) {
  /* Decode SPSSequence<SPSMemoryAccessUInt8Write>
   * Each write is: (ExecutorAddr Addr, uint8_t Value)
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    uint8_t value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return;
    if (ptr + 1 > end)
      return;
    value = *ptr++;

    *(uint8_t *)addr = value;
  }
}

static void stub_mem_write_uint16s_wrapper(const char *ArgData,
                                           size_t ArgSize) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    uint16_t value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return;
    if (ptr + 2 > end)
      return;
    memcpy(&value, ptr, 2);
    ptr += 2;

    *(uint16_t *)addr = value;
  }
}

static void stub_mem_write_uint32s_wrapper(const char *ArgData,
                                           size_t ArgSize) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr;
    uint32_t value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return;
    if (ptr + 4 > end)
      return;
    memcpy(&value, ptr, 4);
    ptr += 4;

    *(uint32_t *)addr = value;
  }
}

static void stub_mem_write_uint64s_wrapper(const char *ArgData,
                                           size_t ArgSize) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr, value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return;
    if (sps_read_uint64(&ptr, end, &value) < 0)
      return;

    *(uint64_t *)addr = value;
  }
}

static void stub_mem_write_buffers_wrapper(const char *ArgData,
                                           size_t ArgSize) {
  /* Decode SPSSequence<SPSMemoryAccessBufferWrite>
   * Each write is: (ExecutorAddr Addr, SPSSequence<uint8_t> Buffer)
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr, buf_size;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return;
    if (sps_read_uint64(&ptr, end, &buf_size) < 0)
      return;
    if (ptr + buf_size > end)
      return;

    memcpy((void *)addr, ptr, buf_size);
    ptr += buf_size;
  }
}

static void stub_mem_write_pointers_wrapper(const char *ArgData,
                                            size_t ArgSize) {
  /* Decode SPSSequence<SPSMemoryAccessPointerWrite>
   * Each write is: (ExecutorAddr Addr, ExecutorAddr Value)
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0)
    return;

  for (uint64_t i = 0; i < count; i++) {
    uint64_t addr, value;
    if (sps_read_uint64(&ptr, end, &addr) < 0)
      return;
    if (sps_read_uint64(&ptr, end, &value) < 0)
      return;

    *(uint64_t *)addr = value;
  }
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

static void stub_dylib_open_wrapper(const char *ArgData, size_t ArgSize,
                                    uint8_t *ResultPtr) {
  /* Args: (ExecutorAddr Instance, SPSString Path, uint64_t Mode)
   * Returns: SPSExpected<SPSExecutorAddr> - the dylib handle or error
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_dylib_open_wrapper: failed to read instance\n");
    /* Return error */
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0; /* size = 0 means empty result */
    return;
  }

  /* Read path string */
  char *path;
  uint64_t path_len;
  if (sps_read_string(&ptr, end, &path, &path_len) < 0) {
    DEBUG_LOG("stub_dylib_open_wrapper: failed to read path\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  /* Read mode flags */
  uint64_t mode;
  if (sps_read_uint64(&ptr, end, &mode) < 0) {
    DEBUG_LOG("stub_dylib_open_wrapper: failed to read mode\n");
    free(path);
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
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
    /* Return error */
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  DEBUG_LOG("stub_dylib_open_wrapper: dlopen succeeded, handle=0x%lx\n",
            (uint64_t)(uintptr_t)handle);

  /* Return success with handle
   * Format: [size:8][has_value:1_byte][value:8_if_has_value]
   * SPSExpected with success = size=9, has_value=1, value=handle_addr
   */
  uint8_t *result = ResultPtr;
  uint64_t result_size = 9; /* 1 byte flag + 8 bytes handle */
  memcpy(result, &result_size, 8);
  result[8] = 1; /* Success flag */
  uint64_t handle_addr = (uint64_t)(uintptr_t)handle;
  memcpy(result + 9, &handle_addr, 8);
}

static void stub_dylib_lookup_wrapper(const char *ArgData, size_t ArgSize,
                                      uint8_t *ResultPtr) {
  /* Args: (ExecutorAddr Instance, ExecutorAddr Handle, SPSRemoteSymbolLookupSet)
   * Returns: SPSExpected<SPSSequence<SPSExecutorSymbolDef>>
   *
   * For now, just return an empty sequence to satisfy the daemon.
   * Full implementation would need to parse the symbol lookup set and call dlsym.
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  /* Read dylib handle */
  uint64_t handle_addr;
  if (sps_read_uint64(&ptr, end, &handle_addr) < 0) {
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  void *handle = (void *)(uintptr_t)handle_addr;
  DEBUG_LOG("stub_dylib_lookup_wrapper: handle=0x%lx\n", handle_addr);

  /* Read symbol lookup set - for now just count symbols */
  uint64_t num_symbols;
  if (sps_read_uint64(&ptr, end, &num_symbols) < 0) {
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  DEBUG_LOG("stub_dylib_lookup_wrapper: looking up %lu symbols\n", num_symbols);

  /* For each symbol in the lookup set */
  sps_buffer_t result_buf;
  sps_buffer_init(&result_buf, 1024);

  /* Write success flag (1 byte = 1 for success) */
  uint8_t success_flag = 1;
  memcpy(result_buf.data, &success_flag, 1);
  result_buf.size = 1;

  /* Write sequence size (number of symbols found) */
  sps_write_uint64(&result_buf, num_symbols);

  /* For each symbol, read name and lookup */
  for (uint64_t i = 0; i < num_symbols; i++) {
    char *sym_name;
    uint64_t name_len;
    if (sps_read_string(&ptr, end, &sym_name, &name_len) < 0) {
      sps_buffer_free(&result_buf);
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }

    /* Read required flag */
    uint8_t required;
    if (ptr >= end) {
      free(sym_name);
      sps_buffer_free(&result_buf);
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
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
      sps_write_uint64(&result_buf, 0);
      uint8_t flag_byte = 0;
      memcpy(result_buf.data + result_buf.size, &flag_byte, 1);
      result_buf.size += 1;
      memcpy(result_buf.data + result_buf.size, &flag_byte, 1);
      result_buf.size += 1;
    } else {
      DEBUG_LOG("    Found at: 0x%lx\n", (uint64_t)(uintptr_t)sym_addr);
      /* Write ExecutorSymbolDef: (ExecutorAddr address, JITSymbolFlags flags)
       * JITSymbolFlags is a tuple of (UnderlyingType, TargetFlagsType)
       * Both are typically uint8_t, so we write them as 1-byte values
       */
      sps_write_uint64(&result_buf, (uint64_t)(uintptr_t)sym_addr);
      /* Flags: UnderlyingType = 0 (no special flags), written as uint8_t */
      uint8_t flag_byte = 0;
      memcpy(result_buf.data + result_buf.size, &flag_byte, 1);
      result_buf.size += 1;
      /* TargetFlags: TargetFlagsType = 0, written as uint8_t */
      memcpy(result_buf.data + result_buf.size, &flag_byte, 1);
      result_buf.size += 1;
    }
  }

  /* Copy result to output buffer */
  uint8_t *result = ResultPtr;
  memcpy(result, &result_buf.size, 8); /* Size prefix */
  memcpy(result + 8, result_buf.data, result_buf.size);

  sps_buffer_free(&result_buf);
}

/* Memory manager implementation using mmap/mprotect/munmap
 * This provides proper memory management with executable permissions for JIT code
 */
#include <sys/mman.h>

static void stub_mem_reserve_wrapper(const char *ArgData, size_t ArgSize,
                                     uint8_t *ResultPtr) {
  /* Args: (ExecutorAddr Instance, uint64_t Size)
   * Returns: SPSExpected<SPSExecutorAddr> - allocated memory address or error
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_mem_reserve_wrapper: failed to read instance\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  /* Read size */
  uint64_t size;
  if (sps_read_uint64(&ptr, end, &size) < 0) {
    DEBUG_LOG("stub_mem_reserve_wrapper: failed to read size\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
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
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  DEBUG_LOG("stub_mem_reserve_wrapper: allocated at 0x%lx\n",
            (uint64_t)(uintptr_t)mem);

  /* Return success with address
   * Format: [size:8][success_flag:1][address:8]
   */
  uint8_t *result = ResultPtr;
  uint64_t result_size = 9; /* 1 byte flag + 8 bytes address */
  memcpy(result, &result_size, 8);
  result[8] = 1; /* Success flag */
  uint64_t mem_addr = (uint64_t)(uintptr_t)mem;
  memcpy(result + 9, &mem_addr, 8);
}

static void stub_mem_finalize_wrapper(const char *ArgData, size_t ArgSize,
                                      uint8_t *ResultPtr) {
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
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  DEBUG_LOG("stub_mem_finalize_wrapper: processing finalize request\n");

  /* Read number of segments */
  uint64_t num_segments;
  if (sps_read_uint64(&ptr, end, &num_segments) < 0) {
    DEBUG_LOG("stub_mem_finalize_wrapper: failed to read num_segments\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  DEBUG_LOG("  Processing %lu segments\n", num_segments);

  /* Process each segment */
  for (uint64_t i = 0; i < num_segments; i++) {
    /* Read RemoteAllocGroup flags (1 byte) */
    if (ptr >= end) {
      DEBUG_LOG("stub_mem_finalize_wrapper: buffer underrun at segment %lu\n", i);
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }
    uint8_t prot_flags = *ptr++;

    /* Read segment address */
    uint64_t addr;
    if (sps_read_uint64(&ptr, end, &addr) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read address\n");
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }

    /* Read segment size */
    uint64_t size;
    if (sps_read_uint64(&ptr, end, &size) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read size\n");
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }

    /* Read content sequence length */
    uint64_t content_len;
    if (sps_read_uint64(&ptr, end, &content_len) < 0) {
      DEBUG_LOG("stub_mem_finalize_wrapper: failed to read content_len\n");
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }

    /* Skip content bytes */
    if (ptr + content_len > end) {
      DEBUG_LOG("stub_mem_finalize_wrapper: content out of bounds\n");
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
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
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }
  }

  /* Skip the actions sequence for now (we don't need to process them) */
  /* Actions are: SPSSequence<SPSAllocActionCallPair> */
  uint64_t num_actions;
  if (sps_read_uint64(&ptr, end, &num_actions) < 0) {
    DEBUG_LOG("stub_mem_finalize_wrapper: failed to read num_actions\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  DEBUG_LOG("  Skipping %lu actions\n", num_actions);
  /* We could parse and execute actions here, but for now just skip them */

  /* Return success (empty error)
   * Format: [size:8][HasError:1_byte]
   * SPSError format: bool HasError (0=success, 1=error), followed by error string if HasError==1
   */
  uint8_t *result = ResultPtr;
  uint64_t result_size = 1; /* Just HasError bool */
  memcpy(result, &result_size, 8);
  result[8] = 0; /* HasError=false (0 = no error) */
}

static void stub_mem_deallocate_wrapper(const char *ArgData, size_t ArgSize,
                                        uint8_t *ResultPtr) {
  /* Args: (ExecutorAddr Instance, SPSSequence<SPSExecutorAddr>)
   * Returns: SPSError - empty for success, error message for failure
   */
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read instance pointer (ignored) */
  uint64_t instance;
  if (sps_read_uint64(&ptr, end, &instance) < 0) {
    DEBUG_LOG("stub_mem_deallocate_wrapper: failed to read instance\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
  }

  /* Read sequence of allocation descriptors
   * Each descriptor is actually a struct with address and size
   * For simple implementation, we'll assume each entry is just an address
   * and we need to track sizes separately (or just leak for now)
   */
  uint64_t count;
  if (sps_read_uint64(&ptr, end, &count) < 0) {
    DEBUG_LOG("stub_mem_deallocate_wrapper: failed to read count\n");
    uint64_t *result = (uint64_t *)ResultPtr;
    result[0] = 0;
    return;
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
      uint64_t *result = (uint64_t *)ResultPtr;
      result[0] = 0;
      return;
    }

    DEBUG_LOG("  Would munmap address 0x%lx (size unknown, skipping)\n", addr);
    /* TODO: Track allocation sizes to properly munmap(addr, size) */
  }

  /* Return success (empty error)
   * Format: [size:8][HasError:1_byte]
   * SPSError format: bool HasError (0=success, 1=error), followed by error string if HasError==1
   */
  uint8_t *result = ResultPtr;
  uint64_t result_size = 1; /* Just HasError bool */
  memcpy(result, &result_size, 8);
  result[8] = 0; /* HasError=false (0 = no error) */
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

static int send_setup_message(int fd) {
  /* Setup message format (SPS encoded):
   * - target_triple: string
   * - page_size: uint64_t
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
  sps_write_string(&setup_data, "llvm_orc_registerEHFrameSectionWrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)llvm_orc_registerEHFrameSectionWrapper);

  sps_write_string(&setup_data, "llvm_orc_deregisterEHFrameSectionWrapper");
  sps_write_uint64(&setup_data,
                   (uint64_t)(uintptr_t)llvm_orc_deregisterEHFrameSectionWrapper);

  DEBUG_LOG(
      "Sending Setup message: triple=%s, page_size=%lu, bootstrap_symbols=17\n",
      triple, page_size);

  /* Send Setup message */
  epc_message_t setup_msg = {.opcode = OPCODE_SETUP,
                             .seqno = 0,
                             .tag_addr = 0,
                             .arg_bytes = setup_data.data,
                             .arg_size = setup_data.size};

  int ret = send_epc_message(fd, &setup_msg);
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

static int call_wrapper_function(int fd, uint64_t fn_addr, const uint8_t *data,
                                 size_t args_size, uint8_t **result,
                                 size_t *result_size) {
  /* Send CallWrapper message */
  epc_message_t call_msg = {.opcode = OPCODE_CALLWRAPPER,
                            .seqno = __sync_fetch_and_add(&g_next_seqno, 1),
                            .tag_addr = fn_addr,
                            .arg_bytes = (uint8_t *)data,
                            .arg_size = args_size};

  DEBUG_LOG("Calling wrapper function at 0x%lx with seqno %lu\n", fn_addr,
            call_msg.seqno);

  if (send_epc_message(fd, &call_msg) < 0) {
    ERROR_LOG("Failed to send CallWrapper message\n");
    return -1;
  }

  /* Wait for Result message - use message_loop_until to handle any nested
   * CallWrapper messages from the daemon (e.g., memory reserve requests)
   */
  epc_message_t result_msg;
  if (message_loop_until(fd, OPCODE_RESULT, &result_msg) < 0) {
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

  /* The Result message arg_bytes contain the raw WrapperFunctionResult data.
   * The size is already in result_msg.arg_size (no size prefix in the data).
   * For void returns, the result may be empty (0 bytes).
   * Out-of-band errors are sent separately via a different mechanism (not as Result messages).
   */
  if (result_msg.arg_size == 0) {
    /* Empty result - void return */
    *result = NULL;
    *result_size = 0;
  } else {
    /* Non-empty result - copy it */
    *result = malloc(result_msg.arg_size);
    if (!*result) {
      free_epc_message(&result_msg);
      return -1;
    }
    memcpy(*result, result_msg.arg_bytes, result_msg.arg_size);
    *result_size = result_msg.arg_size;
  }

  free_epc_message(&result_msg);
  return 0;
}

/* ============================================================================
 * Message Handling
 * ============================================================================
 */

/* Handle CallWrapper message - find and invoke the wrapper function */
static int handle_callwrapper_message(int fd, const epc_message_t *msg) {
  /* tag_addr contains the function pointer to call */
  typedef void (*WrapperFn)(const char *, size_t, uint8_t *);
  WrapperFn fn = (WrapperFn)(uintptr_t)msg->tag_addr;

  DEBUG_LOG("Handling CallWrapper: fn=0x%lx, seqno=%lu, arg_size=%zu\n",
            msg->tag_addr, msg->seqno, msg->arg_size);

  /* Allocate result buffer - wrapper functions write result here
   * Result format is WrapperFunctionResult: [size:8][data:variable]
   * We allocate a generous buffer since we don't know the result size upfront
   */
  uint8_t result_buf[4096];
  memset(result_buf, 0, sizeof(result_buf));

  /* Call the wrapper function */
  fn((const char *)msg->arg_bytes, msg->arg_size, result_buf);

  /* Extract result size from first 8 bytes */
  uint64_t result_data_size;
  memcpy(&result_data_size, result_buf, 8);

  /* Send Result message with the result data (skip the 8-byte size prefix) */
  epc_message_t result_msg = {.opcode = OPCODE_RESULT,
                              .seqno = msg->seqno,
                              .tag_addr = 0,
                              .arg_bytes = result_buf + 8,
                              .arg_size = result_data_size};

  if (send_epc_message(fd, &result_msg) < 0) {
    ERROR_LOG("Failed to send Result message\n");
    return -1;
  }

  DEBUG_LOG("Sent Result for seqno=%lu, result_size=%lu\n", msg->seqno,
            result_data_size);
  return 0;
}

/* Message loop - process messages until we receive a specific stop opcode
 * stop_opcode: The opcode that causes the loop to exit (e.g., OPCODE_SETUP or
 * OPCODE_HANGUP) Returns: 0 on success (when stop_opcode is received), -1 on
 * error On success, the stop message is left in *stop_msg for the caller to
 * process
 */
static int message_loop_until(int fd, uint64_t stop_opcode,
                              epc_message_t *stop_msg) {
  DEBUG_LOG("Entering message loop, waiting for opcode 0x%02lx\n", stop_opcode);

  while (1) {
    epc_message_t msg;
    if (recv_epc_message(fd, &msg) < 0) {
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

    } else if (msg.opcode == OPCODE_CALLWRAPPER) {
      /* Handle RPC call from daemon */
      if (handle_callwrapper_message(fd, &msg) < 0) {
        ERROR_LOG("Failed to handle CallWrapper message\n");
        free_epc_message(&msg);
        return -1;
      }
      free_epc_message(&msg);
      /* Continue loop */

    } else if (msg.opcode == OPCODE_HANGUP) {
      /* Daemon disconnected */
      ERROR_LOG("Daemon sent Hangup\n");
      free_epc_message(&msg);
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

static void cleanup_daemon(void) {
  if (g_daemon_fd >= 0) {
    /* Send hangup message only if we spawned the daemon */
    if (g_daemon_pid > 0) {
      epc_message_t hangup = {.opcode = OPCODE_HANGUP,
                              .seqno = 0,
                              .tag_addr = 0,
                              .arg_bytes = NULL,
                              .arg_size = 0};
      send_epc_message(g_daemon_fd, &hangup);
    }

    close(g_daemon_fd);
    g_daemon_fd = -1;
  }
  if (g_daemon_pid > 0) {
    kill(g_daemon_pid, SIGTERM);
    waitpid(g_daemon_pid, NULL, 0);
    g_daemon_pid = -1;
  }
}

static void to_lowercase(char *str) {
  for (; *str; ++str)
    *str = tolower(*str);
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

  DEBUG_LOG("Successfully connected to existing daemon\n");
  return fd;
}

static void initialize_daemon(void) {
  g_debug = checkenv("AUTOJIT_DEBUG");
  DEBUG_LOG("Initializing daemon\n");

  /* First, try to connect to an existing daemon */
  int daemon_fd = -1;
  if (!checkenv("AUTOJITD_FORCE_SPAWN"))
    daemon_fd = connect_to_existing_daemon();

  if (checkenv("AUTOJITD_FORCE_DAEMON") && daemon_fd < 0) {
    ERROR_LOG("connecting to daemon failed: %s\n", strerror(errno));
    exit(1);
  }

  if (daemon_fd >= 0) {
    /* Successfully connected to existing daemon */
    g_daemon_fd = daemon_fd;
    g_daemon_pid = -1; /* No child process to track */
    DEBUG_LOG("Connected to existing daemon\n");
  } else {
    /* No existing daemon found - spawn a new one */
    DEBUG_LOG("No existing daemon found, spawning new daemon\n");

    /* Create socketpair for bidirectional communication */
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
      ERROR_LOG("socketpair failed: %s\n", strerror(errno));
      exit(1);
    }

    /* Fork daemon process */
    pid_t pid = fork();
    if (pid < 0) {
      ERROR_LOG("fork failed: %s\n", strerror(errno));
      exit(1);
    }

    if (pid == 0) {
      /* Child process - exec daemon */
      close(fds[1]);

      /* Redirect stdin/stdout to socket */
      dup2(fds[0], STDIN_FILENO);
      dup2(fds[0], STDOUT_FILENO);
      if (fds[0] > STDERR_FILENO)
        close(fds[0]);

      /* Find daemon executable */
      const char *daemon_path = getenv("AUTOJIT_DAEMON_PATH");
      if (!daemon_path)
        daemon_path = "autojitd";

      execl(daemon_path, "autojitd", "--stdio", NULL);
      fprintf(stderr, "autojit-stub: failed to exec daemon '%s': %s\n",
              daemon_path, strerror(errno));
      _exit(1);
    }

    /* Parent process */
    close(fds[0]);
    g_daemon_fd = fds[1];
    g_daemon_pid = pid;

    DEBUG_LOG("Daemon started with pid %d\n", g_daemon_pid);
  }

  if (checkenv("AUTOJIT_WAIT_FOR_DEBUGGER")) {
    int c;
    printf("Waiting for debugger. Press ENTER to continue...");
    while ((c = getchar()) != '\n' && c != EOF) ;
  }

  /* Send Setup message to daemon */
  if (send_setup_message(g_daemon_fd) < 0) {
    ERROR_LOG("Failed to send Setup message to daemon\n");
    cleanup_daemon();
    exit(1);
  }

  /* Message loop: process messages until we receive Setup message from daemon
   * The daemon may send CallWrapper messages during initialization before
   * sending its Setup message. message_loop_until will handle these.
   */
  epc_message_t setup_msg;
  if (message_loop_until(g_daemon_fd, OPCODE_SETUP, &setup_msg) < 0) {
    ERROR_LOG("Failed to receive Setup message from daemon\n");
    cleanup_daemon();
    exit(1);
  }

  DEBUG_LOG("Received Setup message\n");

  /* Parse bootstrap symbols */
  if (parse_setup_message(&setup_msg) < 0) {
    ERROR_LOG("Failed to parse Setup message\n");
    free_epc_message(&setup_msg);
    cleanup_daemon();
    exit(1);
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
 * Args: SPSExecutorAddrRange (Start:uint64_t, Size:uint64_t)
 * Returns: SPSError (bool HasError, optional error string)
 */
static void llvm_orc_registerEHFrameSectionWrapper(const char *ArgData,
                                                    size_t ArgSize,
                                                    uint8_t *ResultPtr) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read ExecutorAddrRange: (Start, Size) */
  uint64_t start_addr, size;
  if (sps_read_uint64(&ptr, end, &start_addr) < 0 ||
      sps_read_uint64(&ptr, end, &size) < 0) {
    DEBUG_LOG("llvm_orc_registerEHFrameSectionWrapper: failed to read args\n");
    /* Return error */
    uint8_t *result = ResultPtr;
    uint64_t result_size = 1;
    memcpy(result, &result_size, 8);
    result[8] = 1; /* HasError = true */
    return;
  }

  DEBUG_LOG("Registering EH frame section: addr=0x%lx, size=%lu\n", start_addr,
            size);

  /* Call __register_frame with the start address
   * Note: libgcc expects a pointer to the start of the .eh_frame section.
   * libunwind might require walking the section and registering each FDE,
   * but for now we assume libgcc behavior (simpler and more common).
   */
  __register_frame((const void *)(uintptr_t)start_addr);

  /* Return success (empty error) */
  uint8_t *result = ResultPtr;
  uint64_t result_size = 1;
  memcpy(result, &result_size, 8);
  result[8] = 0; /* HasError = false */
}

/* Wrapper for deregistering EH frames - called by daemon via RPC
 * Args: SPSExecutorAddrRange (Start:uint64_t, Size:uint64_t)
 * Returns: SPSError (bool HasError, optional error string)
 */
static void llvm_orc_deregisterEHFrameSectionWrapper(const char *ArgData,
                                                      size_t ArgSize,
                                                      uint8_t *ResultPtr) {
  const uint8_t *ptr = (const uint8_t *)ArgData;
  const uint8_t *end = ptr + ArgSize;

  /* Read ExecutorAddrRange: (Start, Size) */
  uint64_t start_addr, size;
  if (sps_read_uint64(&ptr, end, &start_addr) < 0 ||
      sps_read_uint64(&ptr, end, &size) < 0) {
    DEBUG_LOG("llvm_orc_deregisterEHFrameSectionWrapper: failed to read args\n");
    /* Return error */
    uint8_t *result = ResultPtr;
    uint64_t result_size = 1;
    memcpy(result, &result_size, 8);
    result[8] = 1; /* HasError = true */
    return;
  }

  DEBUG_LOG("Deregistering EH frame section: addr=0x%lx, size=%lu\n", start_addr,
            size);

  /* Call __deregister_frame with the start address */
  __deregister_frame((const void *)(uintptr_t)start_addr);

  /* Return success (empty error) */
  uint8_t *result = ResultPtr;
  uint64_t result_size = 1;
  memcpy(result, &result_size, 8);
  result[8] = 0; /* HasError = false */
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
  DEBUG_LOG("First 16 bytes (hex): ");
  for (size_t i = 0; i < (args.size < 16 ? args.size : 16); i++) {
    fprintf(stderr, "%02x ", args.data[i]);
  }
  fprintf(stderr, "\n");

  /* Call RPC function */
  uint8_t *result;
  size_t result_size;

  if (call_wrapper_function(g_daemon_fd, g_register_fn_addr, args.data,
                            args.size, &result, &result_size) < 0) {
    ERROR_LOG("Failed to call register RPC\n");
    sps_buffer_free(&args);
    exit(1);
  }

  sps_buffer_free(&args);
  free(result);

  DEBUG_LOG("Module registered successfully\n");
}

void __llvm_autojit_materialize(void **GuidInPtrOut) {
  if (!GuidInPtrOut || *GuidInPtrOut == NULL) {
    ERROR_LOG("invalid parameters\n");
    exit(1);
  }

  /* Ensure daemon is initialized */
  pthread_once(&g_init_once, initialize_daemon);

  uint64_t guid = (uint64_t)(uintptr_t)(*GuidInPtrOut);
  DEBUG_LOG("Requesting function: __llvm_autojit_fn_%lu\n", guid);

  /* Encode arguments: SPSArgList<uint64_t> */
  sps_buffer_t args;
  sps_buffer_init(&args, 8);
  sps_write_uint64(&args, guid);

  /* Call RPC function */
  uint8_t *result;
  size_t result_size;

  if (call_wrapper_function(g_daemon_fd, g_materialize_fn_addr, args.data,
                            args.size, &result, &result_size) < 0) {
    ERROR_LOG("Failed to call materialize RPC\n");
    sps_buffer_free(&args);
    exit(1);
  }

  sps_buffer_free(&args);

  /* Decode result: SPSArgList<uint64_t> */
  if (result_size != 8) {
    ERROR_LOG("Invalid result size: expected 8, got %zu\n", result_size);
    free(result);
    exit(1);
  }

  uint64_t func_addr;
  memcpy(&func_addr, result, 8);
  free(result);

  DEBUG_LOG("Function materialized at address 0x%016lx\n", func_addr);

  /* Update pointer with returned address */
  *GuidInPtrOut = (void *)(uintptr_t)func_addr;
}
