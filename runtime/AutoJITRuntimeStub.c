#include "AutoJITRuntime.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

  /* Wait for Result message */
  epc_message_t result_msg;
  if (recv_epc_message(fd, &result_msg) < 0) {
    ERROR_LOG("Failed to receive Result message\n");
    return -1;
  }

  if (result_msg.opcode != OPCODE_RESULT) {
    ERROR_LOG("Expected Result message, got opcode 0x%02lx\n",
              result_msg.opcode);
    free_epc_message(&result_msg);
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
   * For void returns or out-of-band errors, the result may be empty (0 bytes).
   */
  if (result_msg.arg_size == 0) {
    *result = NULL;
    *result_size = 0;
  } else {
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
 * Daemon Initialization
 * ============================================================================
 */

static void cleanup_daemon(void) {
  if (g_daemon_fd >= 0) {
    /* Send hangup message */
    epc_message_t hangup = {.opcode = OPCODE_HANGUP,
                            .seqno = 0,
                            .tag_addr = 0,
                            .arg_bytes = NULL,
                            .arg_size = 0};
    send_epc_message(g_daemon_fd, &hangup);

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

static void initialize_daemon(void) {
  g_debug = checkenv("AUTOJIT_DEBUG");
  DEBUG_LOG("Initializing daemon\n");

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

    execl(daemon_path, "autojitd", NULL);
    fprintf(stderr, "autojit-stub: failed to exec daemon: %s\n",
            strerror(errno));
    _exit(1);
  }

  /* Parent process */
  close(fds[0]);
  g_daemon_fd = fds[1];
  g_daemon_pid = pid;

  DEBUG_LOG("Daemon started with pid %d\n", g_daemon_pid);
  if (checkenv("AUTOJIT_WAIT_FOR_DEBUGGER")) {
    int c;
    printf("Waiting for debugger. Press ENTER to continue...");
    while ((c = getchar()) != '\n' && c != EOF) {
    }
    getchar();
  }

  /* Wait for Setup message from daemon */
  epc_message_t setup_msg;
  if (recv_epc_message(g_daemon_fd, &setup_msg) < 0) {
    ERROR_LOG("Failed to receive Setup message\n");
    cleanup_daemon();
    exit(1);
  }

  if (setup_msg.opcode != OPCODE_SETUP) {
    ERROR_LOG("Expected Setup message, got opcode 0x%02lx\n", setup_msg.opcode);
    free_epc_message(&setup_msg);
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

  DEBUG_LOG("Materializing function with GUID 0x%016lx\n", guid);

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
