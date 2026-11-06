// Programs might close stdin, stdout or stderr. New files get these descriptors
// then, also the ones for the object cache.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: env AUTOJIT_DIR=%t.dir %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.exe
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t.exe > %t.out
// RUN: FileCheck %s < %t.out
// RUN: ls %t.dir/*.o | count 1
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t.exe > %t.out
// RUN: FileCheck %s < %t.out
//
// CHECK: value: 6

#include <stdio.h>
#include <unistd.h>

int compute(int X) {
  int Sum = 0;
  for (int I = 1; I <= X; I += 1)
    Sum += I;
  return Sum;
}

// The first lazy call comes after closing them
__attribute__((constructor)) static void init(void) {
  close(0);
  close(2);
}

int main(void) {
  printf("value: %d\n", compute(3));
  return 0;
}
