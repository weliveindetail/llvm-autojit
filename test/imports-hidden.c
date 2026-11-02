// Check that lazy code can access hidden symbols of the executable. They are
// not in the dynamic symbol table and the JIT code is far away from them.
//
// RUN: %clang_c -c %S/Inputs/hidden.c -o %t_hidden.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang_c %t.o %t_hidden.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c %t.o %t_hidden.o -rdynamic -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: hiddenFn(HiddenVar) = 43

#include <stdio.h>

__attribute__((visibility("hidden"))) extern int HiddenVar;
__attribute__((visibility("hidden"))) int hiddenFn(int X);

int main() {
  printf("hiddenFn(HiddenVar) = %d\n", hiddenFn(HiddenVar));
  return 0;
}
