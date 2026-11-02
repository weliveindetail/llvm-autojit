// Lazy functions in the executable can interpose symbols that the runtime uses
// itself. In C++20 mode, libstdc++ has no extern templates for std::string and
// the executable exports its own instantiations, even without -rdynamic,
// because libstdc++.so defines them as well. The runtime must not call them,
// because it would re-enter materialization.
//
// REQUIRES: libstdcxx
// RUN: %clang -std=c++20 -fpass-plugin=%autojit_plugin %s -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.exe
// RUN: %t.exe 2>&1 | FileCheck %s
// RUN: %clang -std=c++20 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_nordynamic.exe
// RUN: %t_nordynamic.exe 2>&1 | FileCheck %s

// CHECK: Long enough to need heap allocation

#include <cstdio>
#include <string>

int main(int argc, char *argv[]) {
  std::string Str(argv[0]);
  Str += ": Long enough to need heap allocation";
  printf("%s\n", Str.c_str());
  return 0;
}
