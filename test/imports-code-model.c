// Check that the import table reaches large data with the medium code model.
// The linker places After more than 2GB away from the import table, which a
// 32-bit offset can't reach. Huge is in .lbss and doesn't need memory.
//
// RUN: %clang_c -mcmodel=medium -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c -mcmodel=medium -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: touch() = 3

#include <stdio.h>

char Huge[3UL << 30];
int After[100000];

int touch(void) {
  Huge[sizeof(Huge) - 1] = 1;
  After[99999] = 2;
  return Huge[sizeof(Huge) - 1] + After[99999];
}

int main(void) {
  printf("touch() = %d\n", touch());
  return 0;
}
