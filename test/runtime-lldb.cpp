// Check that LLDB can debug lazy code through the GDB JIT interface. The
// breakpoint is on a line that only exists in the JITed code: static code only
// has the trampoline for jitted(). Matching test for GDB: runtime-gdb.cpp
//
// REQUIRES: lldb
// TPDE doesn't emit debug info
// XFAIL: tpde
//
// RUN: %clang -g %s -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %clang -g %s -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -lautojit_static_debug_ldscript %fsanitize -o %t_remote.exe
//
// RUN: env AUTOJIT_DEBUG=On %lldb \
// RUN:     -o "b runtime-lldb.cpp:$(grep -n 'break here$' %s | head -1 | cut -d: -f1)" \
// RUN:     -o run -o bt -o 'frame variable X' -o continue %t_inprocess.exe 2>&1 | FileCheck %s
// RUN: env AUTOJIT_DEBUG=On %lldb \
// RUN:     -o "b runtime-lldb.cpp:$(grep -n 'break here$' %s | head -1 | cut -d: -f1)" \
// RUN:     -o run -o bt -o 'frame variable X' -o continue %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK-NOT: Cannot enable debugger support
// CHECK: stop reason = breakpoint 1.1
// CHECK: frame #0: {{.*}}`jitted(X=1) at {{.*}}runtime-lldb.cpp:[[@LINE+10]]
// CHECK: (lldb) bt
// CHECK: frame #0: {{.*}}`jitted(X=1) at {{.*}}runtime-lldb.cpp:[[@LINE+8]]
// CHECK: frame #1: {{.*}}`main(argc=1, {{.*}}) at {{.*}}runtime-lldb.cpp:[[@LINE+14]]
// CHECK: (lldb) frame variable X
// CHECK: (int) X = 1
// CHECK: Result: 3
// CHECK: exited with status = 0

int jitted(int X) {
  int Y = X * 2; // break here
  return Y + 1;
}

#include <cstdio>

int main(int argc, char *argv[]) {
  printf("Result: %d\n", jitted(argc));
  return 0;
}
