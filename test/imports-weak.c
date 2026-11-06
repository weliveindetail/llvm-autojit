// Check that undefined weak imports resolve to null in lazy code
//
// RUN: rm -rf %t.dir
// RUN: env AUTOJIT_DIR=%t.dir %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang_c %t.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c %t.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: WeakVar: null
// CHECK: weakFn: null

#include <stdio.h>

extern int WeakVar __attribute__((weak));
void weakFn(void) __attribute__((weak));

int main() {
  printf("WeakVar: %s\n", &WeakVar ? "defined" : "null");
  printf("weakFn: %s\n", weakFn ? "defined" : "null");
  return 0;
}
