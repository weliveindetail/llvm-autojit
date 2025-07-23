// Check that we can't build a simple static executable with TPDE codegen
//
// RUN: clang++ -std=c++20 -stdlib=libc++ -o %t_llvm.exe %s
// RUN: %t_llvm.exe abc | FileCheck %s
// CHECK: argc = 2
//
// RUN: clang++ -std=c++20 -stdlib=libc++ -O0 -o %t_tpde.exe %s -ftpde -ftpde-abort
// XFAIL: *
//   [error] unsupported type: x86_fp80
//   [error] unsupported type: i80
//

#include <cstdio>
#include <format>
#include <string>

int main(int argc, char *argv[]) {
    std::string s = std::format("{}", argc);
    printf("argc = %s\n", s.c_str());
    return 0;
}
