// Check that static initializers run before main in the original order. The
// global's initializer stays in static code, but calls a lazy function. The
// external constructor function is lazy itself.
//
// RUN: %clang -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK:      initHook: G.V = 0
// CHECK-NEXT: Global ctor
// CHECK-NEXT: main: G.V = 42

#include <cstdio>

int compute(int X) { return X * 2; }

struct Global {
  int V;
  Global() : V(compute(21)) { puts("Global ctor"); }
};
Global G;

__attribute__((constructor)) void initHook() {
  printf("initHook: G.V = %d\n", G.V);
}

int main() {
  printf("main: G.V = %d\n", G.V);
  return 0;
}
