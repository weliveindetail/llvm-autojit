// A spawned daemon must exit when its process goes away without a hangup. If it
// lingered, then it would hold on to the program's stderr and hang the pipeline.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t.exe
// RUN: %t.exe 2>&1 | FileCheck %s
// RUN: not --crash %t.exe crash 2>&1 | FileCheck %s
//
// CHECK: lazy: 8
// CHECK-NOT: autojit
//
// The stream can't recover from a corrupt message, so the daemon must stop
// RUN: %t.exe garbage 2>&1 | FileCheck --check-prefix=GARBAGE %s
// GARBAGE: Message size too small
// GARBAGE: daemon is gone

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int lazy(int X) {
  int Sum = 0;
  for (int I = 0; I < X; I += 1)
    Sum += I % 2 == 0 ? 2 : 0;
  return Sum + X - 1;
}

static void corruptStream(void) {
  char Zeros[32] = {0};
  struct stat Stat;
  for (int FD = 3; FD < 64; FD += 1)
    if (fstat(FD, &Stat) == 0 && S_ISSOCK(Stat.st_mode) &&
        write(FD, Zeros, sizeof(Zeros)) != sizeof(Zeros))
      abort();
  // We keep the connection open, so only the error can stop the daemon
  alarm(30);
  wait(NULL);
  puts("daemon is gone");
  fflush(stdout);
}

int main(int Argc, char **Argv) {
  printf("lazy: %d\n", lazy(3) + 2);
  fflush(stdout);
  if (Argc > 1 && strcmp(Argv[1], "garbage") == 0) {
    corruptStream();
    _exit(0);
  }
  if (Argc > 1)
    abort();
  _exit(0);
}
