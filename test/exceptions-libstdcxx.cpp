// TODO: double-check with orc-rt and libcxx
// REQUIRES: libstdcxx

// RUN: %clang -fexceptions -frtti -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic -stdlib=libstdc++ -o %t.exe %s

// RUN: %t.exe
// RUN: %t.exe catch-me-if-you-can | FileCheck %s

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
