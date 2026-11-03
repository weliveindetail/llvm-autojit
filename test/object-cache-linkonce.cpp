// Check that cached objects don't depend on which modules were loaded before.
// Both lazy modules define the inline functions of Shape and its vtable. The
// linker keeps the trampolines of linkonce-b.cpp, because it comes first. The
// first run loads the module of linkonce-a.cpp first and then the one of
// linkonce-b.cpp, and caches their objects. The second run only loads the one
// of linkonce-b.cpp from the cache, so it must contain its own definitions.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: env AUTOJIT_DIR=%t.dir %clang -I%S/Inputs -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: env AUTOJIT_DIR=%t.dir %clang -I%S/Inputs -fpass-plugin=%autojit_plugin -c %S/Inputs/linkonce-a.cpp -o %t_a.o
// RUN: env AUTOJIT_DIR=%t.dir %clang -I%S/Inputs -fpass-plugin=%autojit_plugin -c %S/Inputs/linkonce-b.cpp -o %t_b.o
// RUN: %clang %t.o %t_b.o %t_a.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.exe
//
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t.exe both | FileCheck --check-prefix=BOTH %s
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t.exe b | FileCheck --check-prefix=B %s
//
// BOTH: a = 42, b = 43
// B: b = 43

#include "linkonce.h"

#include <cstdio>
#include <cstring>

int main(int argc, char *argv[]) {
  if (argc > 1 && strcmp(argv[1], "both") == 0) {
    // The module of linkonce-a.cpp must be loaded first
    int A = callA();
    int B = callB();
    printf("a = %d, b = %d\n", A, B);
  } else
    printf("b = %d\n", callB());
  return 0;
}
