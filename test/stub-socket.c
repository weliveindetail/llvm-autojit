// The stub's socket must stay invisible to the program. It must not take over a
// standard stream that the program closed and programs that we exec don't inherit
// it. This holds for a spawned and for a standalone daemon.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t.exe
// RUN: %t.exe | FileCheck %s
// RUN: sh %S/Inputs/with-daemon.sh %t.sock %t.exe | FileCheck %s
//
// CHECK: stdin is closed: 1
// CHECK: sockets after exec: 0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

// Runs in static code before the first lazy call
__attribute__((constructor)) static void closeStdin(void) { close(0); }

int main(void) {
  struct stat Stat;
  printf("stdin is closed: %d\n", fstat(0, &Stat) != 0 && errno == EBADF);
  fflush(stdout);
  printf("sockets after exec: ");
  fflush(stdout);
  // grep fails if it counts nothing, so we don't check the result
  system("ls -l /proc/self/fd | grep -c socket");
  return 0;
}
