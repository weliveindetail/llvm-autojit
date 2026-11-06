// One lazy module can be part of several images, e.g. with a static library that
// links into two shared libraries. Their imports have different addresses.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir/lld
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -c %S/Inputs/two-images-common.c -o %t.dir/common.o
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -DNAME=fa -c %S/Inputs/two-images-lib.c -o %t.dir/a.o
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -DNAME=fb -c %S/Inputs/two-images-lib.c -o %t.dir/b.o
// RUN: %clang_c -shared -Wl,-Bsymbolic %t.dir/a.o %t.dir/common.o -o %t.dir/liba.so
// RUN: %clang_c -shared -Wl,-Bsymbolic %t.dir/b.o %t.dir/common.o -o %t.dir/libb.so
// RUN: %clang_c %s -L%t.dir -Wl,-rpath,%t.dir -la -lb -L%autojit_runtime_dir -Wl,-rpath,%autojit_runtime_dir -lautojit-runtime -o %t.dir/inprocess
// RUN: %t.dir/inprocess | FileCheck %s
// RUN: %clang_c %s -L%t.dir -Wl,-rpath,%t.dir -la -lb -L%autojit_runtime_dir -Wl,-rpath,%autojit_runtime_dir -lautojit-stub -o %t.dir/remote
// RUN: %t.dir/remote | FileCheck %s
//
// With lld and -Bsymbolic, each library binds to its own stub
// RUN: %if lld %{ %clang_c -fuse-ld=lld -shared -Wl,-Bsymbolic %t.dir/a.o %t.dir/common.o -o %t.dir/lld/liba.so %}
// RUN: %if lld %{ %clang_c -fuse-ld=lld -shared -Wl,-Bsymbolic %t.dir/b.o %t.dir/common.o -o %t.dir/lld/libb.so %}
// RUN: %if lld %{ %clang_c -fuse-ld=lld %s -L%t.dir/lld -Wl,-rpath,%t.dir/lld -la -lb -o %t.dir/lld/exe %}
// RUN: %if lld %{ %t.dir/lld/exe | FileCheck %s %}
//
// Each image has its own counter
// CHECK: 1 1 2 2

#include <stdio.h>

int fa(void);
int fb(void);

int main(void) {
  int A1 = fa();
  int B1 = fb();
  int A2 = fa();
  int B2 = fb();
  printf("%d %d %d %d\n", A1, B1, A2, B2);
  return 0;
}
