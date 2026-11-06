// The runtime runs the passes that the compiler would have run on the lazy module.
//
// With -O2, lazy functions get optimized. The helper only has one caller and
// disappears from the object. Without passes it stays.
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: env AUTOJIT_DIR=%t.dir %clang -O2 -g -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_opt.exe
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t_opt.exe | FileCheck %s
// RUN: %llvm-nm %t.dir/*_r?.o | FileCheck --check-prefix=OPT %s
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE AUTOJIT_SKIP_PASSES=On %t_opt.exe | FileCheck %s
// RUN: %llvm-nm %t.dir/*_nopasses.o | FileCheck --check-prefix=SKIP %s
// CHECK: helper: 3
// OPT-NOT: helperFn
// SKIP: helperFn
//
// Diagnostics from the passes must not end up in the output of the program
// RUN: %t_opt.exe 2>&1 | FileCheck --check-prefix=QUIET %s
// QUIET-NOT: warning
//
// A pass that the runtime doesn't know is a hard error
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-pipeline=no-such-pass %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_bad.exe
// RUN: not %t_bad.exe 2>&1 | FileCheck --check-prefix=BAD %s
// BAD: Failed to run recorded passes on {{.*}}: unknown pass name 'no-such-pass'

#include <cstdio>

inline int helperFn(int X) { return X + 1; }

volatile int Volatile;

// Clang warns "loop not vectorized"
int sumVolatile(int N) {
  int Sum = 0;
#pragma clang loop vectorize(enable)
  for (int I = 0; I < N; I += 1)
    Sum += Volatile;
  return Sum;
}

int main(int Argc, char **) {
  printf("helper: %d\n", helperFn(Argc + 1) + sumVolatile(Argc));
  return 0;
}
