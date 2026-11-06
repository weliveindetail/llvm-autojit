// Materialization does file I/O and memory mapping, which must not change errno.
// Code often calls one of its own functions before it reads errno.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/errno-lib.c -o %t.dir/lib.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main.o
// RUN: %clang_c %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/inprocess
// RUN: %t.dir/inprocess | FileCheck %s
// RUN: %clang_c %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.dir/remote
// RUN: %t.dir/remote | FileCheck %s
//
// CHECK: from static code: 1
// CHECK: from lazy code: 1

#include <errno.h>
#include <stdio.h>

int helper(int X);
int otherHelper(int X, ...);

// Stays in static code, so that it comes first
__attribute__((constructor)) static void init(void) {
  errno = ENOTDIR;
  helper(1);
  printf("from static code: %d\n", errno == ENOTDIR);
}

int main(void) {
  errno = EBADF;
  otherHelper(2);
  printf("from lazy code: %d\n", errno == EBADF);
  return 0;
}
