/*
 * AutoJIT Runtime Stub - Pure C implementation
 *
 * This is a minimal, self-contained stub that forks the autojitd daemon
 * and communicates via LLVM's SimpleRemoteEPC protocol over a Unix socketpair.
 *
 * No external dependencies except libc and pthread.
 */

#include "AutoJITRuntime.h"

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
 * SimpleRemoteEPC Wire Protocol (minimal subset)
 * ============================================================================
 *
 * Message format: [OpCode:1][SeqNo:8][TagAddr:8][ArgBytes:variable]
 *
 * We implement just enough to call wrapper functions on the daemon side.
 * The daemon uses full LLVM SimpleRemoteEPCServer which handles the protocol.
 */

#define OPCODE_SETUP       0x00
#define OPCODE_HANGUP      0x01
#define OPCODE_RESULT      0x02
#define OPCODE_CALLWRAPPER 0x03

/* Global state */
static int g_daemon_fd = -1;
static pid_t g_daemon_pid = -1;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_io_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_next_seqno = 1;

/* Cached function addresses from daemon */
static uint64_t g_register_fn_addr = 0;
static uint64_t g_materialize_fn_addr = 0;

/* Debug logging controlled by AUTOJIT_DEBUG */
static int g_debug = 0;

#define DEBUG_LOG(...) \
    do { if (g_debug) fprintf(stderr, "autojit-stub: " __VA_ARGS__); } while (0)

#define ERROR_LOG(...) \
    fprintf(stderr, "autojit-stub: " __VA_ARGS__)

/* ============================================================================
 * Low-level I/O
 * ============================================================================ */

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
 * SPS (Simple Packed Serialization) - manual encoding
 * ============================================================================
 *
 * We only need to encode/decode:
 * - uint64_t
 * - string (as uint64_t length + bytes)
 * - void (empty)
 */

static size_t sps_size_uint64(void) {
    return 8;
}

static size_t sps_size_string(const char *str) {
    return 8 + strlen(str);  /* length + data */
}

static void sps_write_uint64(uint8_t **buf, uint64_t value) {
    memcpy(*buf, &value, 8);
    *buf += 8;
}

static void sps_write_string(uint8_t **buf, const char *str) {
    uint64_t len = strlen(str);
    memcpy(*buf, &len, 8);
    *buf += 8;
    memcpy(*buf, str, len);
    *buf += len;
}

static int sps_read_uint64(const uint8_t **buf, const uint8_t *end, uint64_t *value) {
    if (*buf + 8 > end) {
        ERROR_LOG("SPS: buffer underrun reading uint64\n");
        return -1;
    }
    memcpy(value, *buf, 8);
    *buf += 8;
    return 0;
}

/* ============================================================================
 * SimpleRemoteEPC message handling
 * ============================================================================ */

static int send_epc_message(int fd, uint8_t opcode, uint64_t seqno, uint64_t tag_addr,
                            const void *arg_bytes, size_t arg_size) {
    pthread_mutex_lock(&g_io_mutex);

    if (write_all(fd, &opcode, 1) < 0 ||
        write_all(fd, &seqno, 8) < 0 ||
        write_all(fd, &tag_addr, 8) < 0) {
        pthread_mutex_unlock(&g_io_mutex);
        return -1;
    }

    if (arg_size > 0 && write_all(fd, arg_bytes, arg_size) < 0) {
        pthread_mutex_unlock(&g_io_mutex);
        return -1;
    }

    pthread_mutex_unlock(&g_io_mutex);
    return 0;
}

static int recv_epc_message(int fd, uint8_t *opcode, uint64_t *seqno, uint64_t *tag_addr,
                            void **arg_bytes, size_t *arg_size) {
    pthread_mutex_lock(&g_io_mutex);

    if (read_all(fd, opcode, 1) < 0 ||
        read_all(fd, seqno, 8) < 0 ||
        read_all(fd, tag_addr, 8) < 0) {
        pthread_mutex_unlock(&g_io_mutex);
        return -1;
    }

    /* For CALLWRAPPER and RESULT, there are argument bytes following */
    /* We read until the next message header or EOF */
    /* For simplicity, we'll read a fixed buffer and parse from there */
    /* In practice, SimpleRemoteEPC has a length-prefixed format for arg bytes */

    /* The arg bytes are actually variable length and not explicitly sized in the header */
    /* We need to peek ahead or know the size from the message type */
    /* For our minimal implementation, we'll read until we can parse the SPS data */

    /* Actually, let's simplify: for Result messages, we know the structure */
    /* For Setup messages, we need to parse the SPS encoded data */

    /* Let's use a simple approach: read into a large buffer */
    size_t buf_capacity = 65536;
    *arg_bytes = malloc(buf_capacity);
    if (!*arg_bytes) {
        pthread_mutex_unlock(&g_io_mutex);
        return -1;
    }

    /* Read available data - this is tricky without a length prefix */
    /* SimpleRemoteEPC actually expects us to parse the SPS structure */
    /* For now, let's read a small fixed amount for our known message types */

    /* For Result messages containing uint64_t, we expect 8 bytes */
    /* For Setup messages, we need to parse the SPS structure properly */

    /* Simplified: just read what's available without blocking */
    /* This won't work properly - we need the full protocol */

    pthread_mutex_unlock(&g_io_mutex);

    /* This is getting too complex for a pure C implementation */
    /* We need to either: */
    /* 1. Implement full SPS parsing in C */
    /* 2. Use a length-prefixed wrapper */
    /* 3. Link against LLVM's SPS library */

    free(*arg_bytes);
    *arg_bytes = NULL;
    *arg_size = 0;

    ERROR_LOG("recv_epc_message not fully implemented\n");
    return -1;
}

/* ============================================================================
 * Daemon initialization
 * ============================================================================ */

static void cleanup_daemon(void) {
    if (g_daemon_fd >= 0) {
        /* Send hangup message */
        uint8_t opcode = OPCODE_HANGUP;
        write(g_daemon_fd, &opcode, 1);

        close(g_daemon_fd);
        g_daemon_fd = -1;
    }
    if (g_daemon_pid > 0) {
        kill(g_daemon_pid, SIGTERM);
        waitpid(g_daemon_pid, NULL, 0);
        g_daemon_pid = -1;
    }
}

static void initialize_daemon(void) {
    /* Check debug flag */
    const char *debug_env = getenv("AUTOJIT_DEBUG");
    if (debug_env && (strcmp(debug_env, "1") == 0 || strcmp(debug_env, "true") == 0 ||
                      strcmp(debug_env, "on") == 0 || strcmp(debug_env, "yes") == 0)) {
        g_debug = 1;
    }

    DEBUG_LOG("initializing daemon\n");

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
        fprintf(stderr, "autojit-stub: failed to exec daemon: %s\n", strerror(errno));
        _exit(1);
    }

    /* Parent process */
    close(fds[0]);
    g_daemon_fd = fds[1];
    g_daemon_pid = pid;

    DEBUG_LOG("daemon started with pid %d\n", g_daemon_pid);

    /* Wait for Setup message from daemon */
    /* The daemon sends a Setup message containing bootstrap symbols */
    /* For now, we'll skip this and just proceed */
    /* In a full implementation, we'd parse the Setup message to get function addresses */

    /* TODO: Implement Setup message parsing to get g_register_fn_addr and g_materialize_fn_addr */

    /* Register cleanup handler */
    atexit(cleanup_daemon);
}

/* ============================================================================
 * Public API implementation
 * ============================================================================ */

void __llvm_autojit_register(const char *FilePath) {
    if (!FilePath) {
        ERROR_LOG("invalid FilePath parameter\n");
        return;
    }

    /* Ensure daemon is initialized */
    pthread_once(&g_init_once, initialize_daemon);

    /* For now, print an error since full protocol is not implemented */
    ERROR_LOG("AutoJIT stub protocol not fully implemented yet\n");
    ERROR_LOG("Would register: %s\n", FilePath);
}

void __llvm_autojit_materialize(void **GuidInPtrOut) {
    if (!GuidInPtrOut || *GuidInPtrOut == NULL) {
        ERROR_LOG("invalid parameters\n");
        exit(1);
    }

    /* Ensure daemon is initialized */
    pthread_once(&g_init_once, initialize_daemon);

    uint64_t guid = (uint64_t)(uintptr_t)(*GuidInPtrOut);

    ERROR_LOG("AutoJIT stub protocol not fully implemented yet\n");
    ERROR_LOG("Would materialize: 0x%016lx\n", guid);
    exit(1);
}
