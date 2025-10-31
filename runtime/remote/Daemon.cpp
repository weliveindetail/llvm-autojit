#include "AutoJITConfig.h"

#include "runtime/core/AutoJIT.h"
#include "runtime/remote/Session.h"

#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/EPCGenericDylibManager.h"
#include "llvm/ExecutionEngine/Orc/EPCGenericMemoryAccess.h"
#include "llvm/ExecutionEngine/Orc/Shared/SimplePackedSerialization.h"
#include "llvm/ExecutionEngine/Orc/Shared/SimpleRemoteEPCUtils.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Host.h"

#include "llvm/ExecutionEngine/Orc/EPCGenericJITLinkMemoryManager.h"
#include "llvm/ExecutionEngine/Orc/Shared/OrcRTBridge.h"
#include "llvm/Support/FormatVariadic.h"

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace llvm;
using namespace llvm::orc;

static llvm::ExitOnError ExitOnErr("[autojitd] ");
static autojit::AutoJIT *Instance = nullptr;

template <int NumDigits> static void hexstr(char *Buffer, uint64_t Val) {
  static const char HexDigits[] = "0123456789ABCDEF";
  for (int i = NumDigits - 1; i >= 0; i -= 1) {
    Buffer[i] = HexDigits[Val % 16];
    Val /= 16;
  }
}

static std::string blobToHex(const char *ArgData, size_t ArgSize) {
  constexpr size_t MaxBytes = 32;
  std::string Buffer((2 * MaxBytes) +     // Digits
                         (MaxBytes - 1) + // Spaces
                         (MaxBytes / 8) + // extra Spaces
                         3,
                     ' '); // Dots
  char *Pos = Buffer.data();
  size_t End = std::min(MaxBytes, ArgSize);
  for (size_t i = 0; i < End; i += 1) {
    hexstr<2>(Pos, (unsigned char)ArgData[i]);
    Pos += ((i % 8 == 7) ? 4 : 3);
  }
  Pos -= 1;
  if (ArgSize > MaxBytes) {
    Pos[0] = '.';
    Pos[1] = '.';
    Pos[2] = '.';
    Pos += 3;
  }
  *Pos = '\0';
  return Buffer;
}

shared::CWrapperFunctionResult outOfBandError(Twine Msg) {
  std::string Tmp = Msg.str();
  DBG() << "Raise out-of-band error: " << Tmp << "\n";
  return shared::WrapperFunctionResult::createOutOfBandError(Tmp.c_str())
      .release();
}

extern "C" shared::CWrapperFunctionResult
autojit_rpc_register(const char *ArgData, size_t ArgSize) {
  DBG() << "autojit_rpc_register: " << blobToHex(ArgData, ArgSize) << "\n";

  std::string FilePath;
  shared::SPSInputBuffer IB(ArgData, ArgSize);
  if (!shared::SPSArgList<shared::SPSString>::deserialize(IB, FilePath))
    return outOfBandError("Failed to deserialize module path");
  DBG() << "autojit_rpc_register module: " << FilePath << "\n";

  if (!Instance)
    return outOfBandError("JIT not initialized");

  ThreadSafeModule TSM = Instance->loadModule(FilePath);
  if (Error Err = Instance->submit(std::move(TSM))) {
    std::string Message = toString(std::move(Err));
    return outOfBandError("Failed to load module from " + FilePath + ": " +
                          Message);
  }

  return shared::WrapperFunctionResult().release();
}

extern "C" shared::CWrapperFunctionResult
autojit_rpc_materialize(const char *ArgData, size_t ArgSize) {
  DBG() << "autojit_rpc_materialize: " << blobToHex(ArgData, ArgSize) << "\n";

  uint64_t Guid;
  shared::SPSInputBuffer IB(ArgData, ArgSize);
  if (!shared::SPSArgList<uint64_t>::deserialize(IB, Guid))
    return outOfBandError("Failed to deserialize GUID");

  if (!Instance)
    return outOfBandError("JIT not initialized");

  std::string Name = autojit::guidToFnName(Guid);
  DBG() << "Lookup function: " << Name << "\n";

  uint64_t Addr = Instance->lookup(Name.c_str());
  DBG() << "Materialized at address 0x" << format("%016" PRIx64, Addr) << "\n";

  size_t ResultSize = shared::SPSArgList<uint64_t>::size(Addr);
  auto Result = shared::WrapperFunctionResult::allocate(ResultSize);
  shared::SPSOutputBuffer OB(Result.data(), Result.size());
  if (!shared::SPSArgList<uint64_t>::serialize(OB, Addr))
    return outOfBandError("Failed to serialize address");

  return Result.release();
}

class AutoCleanupSocket {
private:
  static int ListenFd_;
  static pid_t DaemonPID_;
  static std::string SocketPath_;

  static int createListenSocket(pid_t DaemonPID, const char *SocketPath) {
    unlink(SocketPath);

    int FD = socket(AF_UNIX, SOCK_STREAM, 0);
    if (FD < 0) {
      LOG() << "Failed to create socket: " << strerror(errno);
      exit(1);
    }

    struct sockaddr_un Addr;
    memset(&Addr, 0, sizeof(Addr));
    Addr.sun_family = AF_UNIX;
    strncpy(Addr.sun_path, SocketPath, sizeof(Addr.sun_path) - 1);

    if (bind(FD, (struct sockaddr *)&Addr, sizeof(Addr)) < 0) {
      close(FD);
      LOG() << "Failed to bind socket: " << strerror(errno);
      exit(1);
    }

    if (::listen(FD, 5) < 0) {
      close(FD);
      unlink(SocketPath);
      LOG() << "Failed to listen on socket: " << strerror(errno);
      exit(1);
    }

    return FD;
  }

  // Abnormal exit should cleanup the socket
  static void signalCleanup(int) {
    atexitCleanup();
    _exit(1);
  }

  // Regular exit should cleanup the socket
  static void atexitCleanup() {
    if (getpid() == DaemonPID_) {
      close(ListenFd_);
      unlink(SocketPath_.c_str());
    }
  }

public:
  static int listen(std::string SocketPath, pid_t DaemonPID) {
    // Install Unix domain socket once
    if (!ListenFd_) {
      ListenFd_ = createListenSocket(DaemonPID, SocketPath.c_str());
      DBG() << "Listening on " << SocketPath << "\n";

      // Save info for unbind during shutdown
      DaemonPID_ = DaemonPID;
      SocketPath_ = std::move(SocketPath);

      std::signal(SIGSEGV, signalCleanup);
      std::signal(SIGABRT, signalCleanup);
      std::signal(SIGFPE, signalCleanup);
      std::signal(SIGILL, signalCleanup);
      std::signal(SIGBUS, signalCleanup);
      std::atexit(atexitCleanup);
    }
    return ListenFd_;
  }

  static int accept(int ListenFd) {
    struct sockaddr_un ClientAddr;
    socklen_t ClientLen = sizeof(ClientAddr);

    int ClientFd =
        ::accept(ListenFd, (struct sockaddr *)&ClientAddr, &ClientLen);
    if (ClientFd < 0) {
      LOG() << "Failed to accept connection: " << strerror(errno);
      exit(1);
    }

    return ClientFd;
  }
};

int AutoCleanupSocket::ListenFd_;
pid_t AutoCleanupSocket::DaemonPID_;
std::string AutoCleanupSocket::SocketPath_;

static std::string getDaemonSocketPath() {
  if (const char *EnvPath = std::getenv("AUTOJIT_SOCKET_PATH"))
    return EnvPath;

  if (const char *RuntimeDir = std::getenv("XDG_RUNTIME_DIR"))
    return std::string(RuntimeDir) + "/autojitd.sock";

  return std::string("/tmp/autojitd-") + std::to_string(getuid()) + ".sock";
}

static int runSession(int InFD, int OutFD) {
  std::unique_ptr<llvm::orc::ExecutionSession> ES;
  autojit::Session Session(InFD, OutFD, ES);

  StringMap<ExecutorAddr> RPCSymbols{
      {"autojit_rpc_register", ExecutorAddr::fromPtr(autojit_rpc_register)},
      {"autojit_rpc_materialize",
       ExecutorAddr::fromPtr(autojit_rpc_materialize)},
  };

  Instance = Session.launch(std::move(ES), std::move(RPCSymbols));

  DBG() << "Connected: enter event loop\n";
  int ExitCode = Session.waitForDisconnect();

  DBG() << "Disconnect: session shutting down\n";
  return ExitCode;
}

int main(int argc, char *argv[]) {
  // Check for --stdio flag
  bool StdioMode = false;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--stdio") == 0) {
      StdioMode = true;
      break;
    }
  }

  pid_t PID = getpid();
  if (StdioMode) {
    // Single connection via stdin/stdout (typically as child process)
    DBG() << "Daemon process " << PID << " runs in stdio mode\n";
    return runSession(STDIN_FILENO, STDOUT_FILENO);
  }

  // Standalone mode: multiple connections via Unix domain socket
  LOG() << "Daemon process " << PID << " runs in standalone mode\n";
  int ListenFd = AutoCleanupSocket::listen(getDaemonSocketPath(), PID);
  while (true) {
    LOG() << "Waiting for connection...\n";
    fflush(stderr);

    // Fork new child process for each connection
    int ClientFd = AutoCleanupSocket::accept(ListenFd);
    PID = fork();
    if (PID < 0) {
      LOG() << "Failed to fork for client connection: " << strerror(errno) << "\n";
      close(ClientFd);
      continue;
    }
    // Parent process continues accepting connections
    if (PID > 0) {
      close(ClientFd);
      continue;
    }
    // Child process handles new connection
    close(ListenFd);
    PID = getpid();
    LOG() << "Accepted connection on fd " << ClientFd << " in sub-process "
          << PID << "\n";
    exit(runSession(ClientFd, ClientFd));
  }

  llvm_unreachable("Daemon can only terminate through signal");
}
