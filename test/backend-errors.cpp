// The backend reports errors while it compiles lazy code. They must show the real
// names and not the ones that we use in the JIT.
//
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe 2>&1 | FileCheck %s
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK-NOT: __autojit_
// CHECK: [autojit-runtime] call to reportError(int) marked "dontcall-error": lazy code must not call this
// CHECK-NOT: __autojit_
// CHECK: result: 3

#include <cstdio>

// Only exists to cause the error. Weak, so the reference from static code resolves
// to null instead of failing in the loader when the linker is LLD.
__attribute__((weak, error("lazy code must not call this"))) void reportError(int);

int compute(int X) {
  int Sum = 0;
  for (int I = 0; I < X; I += 1)
    Sum += I;
  if (X < 0)
    reportError(X);
  return Sum;
}

int main() {
  printf("result: %d\n", compute(3));
  return 0;
}
