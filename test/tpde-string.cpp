// Check that we can't build a simple static executable with TPDE codegen
//
// RUN: clang++ -std=c++20 -stdlib=libc++ -O0 -o %t_tpde.exe %s -ftpde -ftpde-abort
// RUN: clang++ -std=c++20 -stdlib=libc++ -O1 -o %t_tpde.exe %s -ftpde -ftpde-abort
// RUN: %t_tpde.exe | FileCheck %s
//
// CHECK: argv0 = {{.*}}

#include <cstdio>
#include <string>

int main(int argc, char *argv[]) {
    std::string s = argv[0];
    printf("argv0 = %s\n", s.c_str());
    return 0;
}
