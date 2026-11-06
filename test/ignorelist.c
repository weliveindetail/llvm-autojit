// Users can keep functions or whole translation units in static code.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: echo "fun:*Static*" > %t.dir/fun.txt
// RUN: env AUTOJIT_IGNORELIST=%t.dir/fun.txt AUTOJIT_STATIC_THRESHOLD=0 %clang_c -fpass-plugin=%autojit_plugin -S -emit-llvm %s -o - | FileCheck --check-prefix=FUN %s
// FUN-NOT: @__llvm_autojit_ptr_keepStatic
// FUN: @__llvm_autojit_ptr_lazy =
//
// RUN: echo "src:*ignorelist.c" > %t.dir/src.txt
// RUN: env AUTOJIT_IGNORELIST=%t.dir/src.txt AUTOJIT_STATIC_THRESHOLD=0 %clang_c -fpass-plugin=%autojit_plugin -S -emit-llvm %s -o - | FileCheck --check-prefix=SRC %s
// SRC-NOT: __llvm_autojit
//
// RUN: env AUTOJIT_IGNORELIST=%t.dir/fun.txt %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.exe
// RUN: %t.exe | FileCheck %s
// CHECK: 3

#include <stdio.h>

int keepStatic(void) { return 1; }
int lazy(void) { return keepStatic() + 2; }

int main(void) {
  printf("%d\n", lazy());
  return 0;
}
