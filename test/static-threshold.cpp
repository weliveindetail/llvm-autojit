// Small leaf functions stay in static code: they are no bigger than a trampoline
// and don't force the module to compile. The JIT can still inline them.
//
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin -S -emit-llvm %s -o - | FileCheck --check-prefix=IR %s
// RUN: env AUTOJIT_STATIC_THRESHOLD=0 %clang -O0 -fpass-plugin=%autojit_plugin -S -emit-llvm %s -o - | FileCheck --check-prefix=OFF %s
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang -O2 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// The first lazy call needs nothing from the JIT for small functions
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: env AUTOJIT_DIR=%t.dir AUTOJIT_STATS=%t.dir/stats.txt %clang -O0 -fpass-plugin=%autojit_plugin -c %s -o %t.dir/a.o
// RUN: FileCheck --check-prefix=STATS %s < %t.dir/stats.txt
// STATS: static={{[1-9]}}{{[0-9]*}} local={{[0-9]+}} private={{[0-9]+}} direct={{[1-9]}}{{[0-9]*}} proxy=0 {{.*}}static-threshold.cpp
//
// IR-NOT: @__llvm_autojit_ptr__Z6getterv
// IR-DAG: @__llvm_autojit_ptr_main =
// IR-DAG: @__llvm_autojit_ptr__Z5largei =
// IR: define dso_local {{.*}}i32 @_Z6getterv()
// IR: load i32, ptr @Value
// OFF: @__llvm_autojit_ptr__Z6getterv
//
// CHECK: getter: 7
// CHECK: large: 45

#include <cstdio>

int Value = 7;
int getter() { return Value; }

int large(int N) {
  int Sum = 0;
  for (int I = 0; I < N; I += 1) {
    Sum += I;
    Sum ^= 0;
    Sum |= 0;
    Sum &= -1;
  }
  return Sum;
}

int main() {
  printf("getter: %d\n", getter());
  printf("large: %d\n", large(10));
  return 0;
}
