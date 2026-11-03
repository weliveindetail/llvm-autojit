// Check that GDB can debug lazy code through the GDB JIT interface. The
// breakpoint is on a line that only exists in the JITed code: static code only
// has the trampoline for jitted().
//
// REQUIRES: gdb
// TPDE doesn't emit debug info
// XFAIL: tpde
//
// RUN: %clang -g %s -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %clang -g %s -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -lautojit_static_debug-%arch %fsanitize -o %t_remote.exe
//
// RUN: env AUTOJIT_DEBUG=On %gdb -ex 'set breakpoint pending on' \
// RUN:     -ex "break debugger.cpp:$(grep -n 'break here$' %s | head -1 | cut -d: -f1)" \
// RUN:     -ex run -ex bt -ex continue --args %t_inprocess.exe 2>&1 | FileCheck %s
// RUN: env AUTOJIT_DEBUG=On %gdb -ex 'set breakpoint pending on' \
// RUN:     -ex "break debugger.cpp:$(grep -n 'break here$' %s | head -1 | cut -d: -f1)" \
// RUN:     -ex run -ex bt -ex continue --args %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK-NOT: Cannot enable debugger support
// CHECK: Breakpoint 1, jitted (X=1) at {{.*}}debugger.cpp:[[@LINE+7]]
// CHECK: #0  jitted (X=1) at {{.*}}debugger.cpp:[[@LINE+6]]
// CHECK: #1  {{.*}} in main ({{.*}}) at {{.*}}debugger.cpp:[[@LINE+12]]
// CHECK: Result: 3
// CHECK: exited normally

int jitted(int X) {
  int Y = X * 2; // break here
  return Y + 1;
}

#include <cstdio>

int main(int argc, char *argv[]) {
  printf("Result: %d\n", jitted(argc));
  return 0;
}
