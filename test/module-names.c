// One source compiled in different ways gets separate lazy modules, e.g. for a
// static and a shared library. Same with the same relative path in two projects.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir/p1 %t.dir/p2 %t.dir/aj
// RUN: env AUTOJIT_DIR=%t.dir/aj %clang_c -fpass-plugin=%autojit_plugin -DGET_OFFSET=0 -DVALUE=1 -c %s -o %t.dir/a.o
// RUN: env AUTOJIT_DIR=%t.dir/aj %clang_c -fpass-plugin=%autojit_plugin -DGET_OFFSET=0 -DVALUE=2 -c %s -o %t.dir/b.o
// RUN: %clang_c %t.dir/a.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/a
// RUN: %clang_c %t.dir/b.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/b
// RUN: %t.dir/a | FileCheck --check-prefix=FIRST %s
// RUN: %t.dir/b | FileCheck --check-prefix=SECOND %s
// FIRST: value: 1
// SECOND: value: 2
//
// RUN: sed -e 's/GET_OFFSET/1/' %s > %t.dir/p1/main.c
// RUN: sed -e 's/GET_OFFSET/2/' %s > %t.dir/p2/main.c
// RUN: cd %t.dir/p1 && env AUTOJIT_DIR=%t.dir/aj %clang_c -fpass-plugin=%autojit_plugin -DVALUE=10 -c main.c -o main.o && %clang_c main.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o a
// RUN: cd %t.dir/p2 && env AUTOJIT_DIR=%t.dir/aj %clang_c -fpass-plugin=%autojit_plugin -DVALUE=10 -c main.c -o main.o && %clang_c main.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o a
// RUN: %t.dir/p1/a | FileCheck --check-prefix=THIRD %s
// RUN: %t.dir/p2/a | FileCheck --check-prefix=FOURTH %s
// THIRD: value: 11
// FOURTH: value: 12
//
// Output paths don't matter, so we get one lazy module per source and options
// RUN: rm -rf %t.dir/same && mkdir -p %t.dir/same
// RUN: env AUTOJIT_DIR=%t.dir/same %clang_c -fpass-plugin=%autojit_plugin -DGET_OFFSET=0 -DVALUE=1 -c %s -o %t.dir/c.o
// RUN: env AUTOJIT_DIR=%t.dir/same %clang_c -fpass-plugin=%autojit_plugin -DGET_OFFSET=0 -DVALUE=1 -c %s -o %t.dir/d.o
// RUN: ls %t.dir/same/*.bc | count 1

#include <stdio.h>

int get(int X) {
  int Result = X + GET_OFFSET;
  for (int I = 0; I < X; I += 1)
    Result += I > 100000 ? I * I : 0;
  return Result;
}

int main(void) {
  printf("value: %d\n", get(VALUE));
  return 0;
}
