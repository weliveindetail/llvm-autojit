// Exceptions thrown and caught in JITed code. The runtime registers EH frames
// with the unwinder of the program, which is libunwind for libc++ here.
// REQUIRES: libcxx
//
// RUN: %clang -fexceptions -frtti -fpass-plugin=%autojit_plugin -stdlib=libc++ -c %s -o %t.o
// RUN: %clang -stdlib=libc++ %t.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe
// RUN: %t_inprocess.exe catch-me-if-you-can | FileCheck %s
//
// RUN: %clang -stdlib=libc++ %t.o -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe
// RUN: %t_remote.exe catch-me-if-you-can | FileCheck %s

// CHECK: catch-me-if-you-can

#include <cstdio>
#include <stdexcept>

void test_throw(const char *msg) {
  throw std::runtime_error(msg);
}

int main(int argc, char *argv[]) {
  if (argc <= 1)
    return 0;

  try {
    test_throw(argv[1]);
  } catch (std::runtime_error &ex) {
    printf("%s\n", ex.what());
    return 0;
  }
  return 1;
}
