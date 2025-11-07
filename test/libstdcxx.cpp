// RUN: %clang -fpass-plugin=%autojit_plugin -stdlib=libstdc++ -std=c++17 -c %s -o %t.o
//
// RUN: %clang %t.o -rdynamic -lstdc++ -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe 2>&1 | FileCheck %s
//
// RUN: %clang %t.o -rdynamic -lstdc++ -L%autojit_runtime_dir -Wl,--whole-archive -lautojit_static-%arch -Wl,--no-whole-archive %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK-NOT: JIT session error
//
// CHECK: No such file or directory;Is a directory;Invalid argument;Permission denied

// This code is copied from a sample program that runs during the LLVM CMake
// configuration process. It's one of the early candidates for failure when
// building LLVM with autojit:
// https://github.com/llvm/llvm-project/blob/release/20.x/llvm/cmake/modules/GetErrcMessages.cmake
//
#include <cerrno>
#include <iostream>
#include <string>
#include <system_error>

std::string getMessageFor(int err) {
    return std::make_error_code(static_cast<std::errc>(err)).message();
}

int main() {
    std::cout << getMessageFor(ENOENT) << ';' << getMessageFor(EISDIR);
    std::cout << ';' << getMessageFor(EINVAL) << ';' << getMessageFor(EACCES);
    return 0;
}
