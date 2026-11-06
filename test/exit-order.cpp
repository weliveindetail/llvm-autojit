// Global destructors and atexit handlers might call lazy code for the first time
// at exit, so the JIT must stay alive until the end.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/exit-order-lib.cpp -o %t.dir/lib.o
// RUN: %clang %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/inprocess
// RUN: %t.dir/inprocess | FileCheck %s
// RUN: %clang %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t.dir/remote
// RUN: %t.dir/remote | FileCheck %s
//
// CHECK: main
// CHECK: atexit: 3
// CHECK: destructor: 6
// CHECK: fini: 10

#include <cstdio>
#include <cstdlib>

int firstAtExit(int X);
int firstInDtor(int X);
int firstInFini(int X);

// Runs after all global destructors, also the ones of the runtime
__attribute__((destructor)) static void fini() {
  printf("fini: %d\n", firstInFini(4));
  fflush(stdout);
}

struct Global {
  ~Global() {
    printf("destructor: %d\n", firstInDtor(3));
    fflush(stdout);
  }
} G;

int main() {
  atexit([] {
    printf("atexit: %d\n", firstAtExit(3));
    fflush(stdout);
  });
  printf("main\n");
  fflush(stdout);
  return 0;
}
