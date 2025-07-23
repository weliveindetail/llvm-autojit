// Check that we can build a simple static executable with TPDE codegen
//
// RUN: clang++ -std=c++20 -stdlib=libc++ -O0 -o %t_tpde.exe %s -ftpde -ftpde-abort
// RUN: clang++ -std=c++20 -stdlib=libc++ -O1 -o %t_tpde.exe %s -ftpde -ftpde-abort
// RUN: %t_tpde.exe abc | FileCheck %s
//
// CHECK: argc = 2

#include <cstdio>

int main(int argc, char *argv[]) {
    printf("argc = %d\n", argc);
    return 0;
}
