// Tables of label addresses live in static data. The functions they point into
// must stay static as well, or the addresses turn into garbage. Found through a
// SIGBUS in procps.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin -O2 %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.exe
// RUN: %t.exe | FileCheck %s
//
// CHECK: extern 2
// CHECK: static 3

#include <stdio.h>

__attribute__((noinline)) int run_extern(volatile int Idx) {
  static void *const Table[] = {&&a, &&b};
  goto *Table[Idx];
a:
  return 1;
b:
  return 2;
}

__attribute__((noinline)) static int run_static(volatile int Idx) {
  static void *const Table[] = {&&a, &&b};
  goto *Table[Idx];
a:
  return 1;
b:
  return 3;
}

int main() {
  printf("extern %d\n", run_extern(1));
  printf("static %d\n", run_static(1));
  return 0;
}
