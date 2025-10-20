// RUN: %clang -fpass-plugin=%autojit_plugin -stdlib=libc++ -std=c++17 -c %s -o %t_cxx.o
// RUN: %clang %t_cxx.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -lc++ -rdynamic -o %t_cxx.exe
// RUN: %t_cxx.exe | FileCheck %s

// REQUIRES: investigation
// XFAIL: *
// CHECK: No such file or directory;Is a directory;Invalid argument;Permission denied

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
