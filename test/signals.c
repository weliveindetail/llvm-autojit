// A signal handler that re-enters the JIT in the middle of loading a module used
// to fail with "Symbols not found". Handlers wait until materialization is done.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/signals-lib.c -o %t.dir/lib.o
// RUN: %clang_c %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/inprocess
// RUN: %t.dir/inprocess | FileCheck %s
// RUN: %clang_c %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.dir/remote
// RUN: %t.dir/remote | FileCheck %s
//
// CHECK: result: 3
// CHECK: signals: 1

#include <signal.h>
#include <stdio.h>
#include <sys/time.h>

int work(int X);
void handler(int Sig);
extern volatile sig_atomic_t Signals;

__attribute__((constructor)) static void init(void) {
  // Keep firing while we load the module that has the handler
  signal(SIGALRM, handler);
  struct itimerval Timer = {{0, 100}, {0, 100}};
  setitimer(ITIMER_REAL, &Timer, NULL);
}

int main(void) {
  int Result = work(1);
  struct itimerval Off = {{0, 0}, {0, 0}};
  setitimer(ITIMER_REAL, &Off, NULL);
  printf("result: %d\n", Result);
  printf("signals: %d\n", Signals > 0);
  return 0;
}
