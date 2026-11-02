// Check that we detect lazy modules that don't belong to the static object.
// Both compilations write the same lazy module path, because the source path
// is the same. The second one has different imports.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t_v1.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -DV2 -c %s -o %t_v2.o
// RUN: %clang_c %t_v1.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_v1.exe
// RUN: not %t_v1.exe 2>&1 | FileCheck %s
//
// CHECK: doesn't match the import table of its static object

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
#ifdef V2
  return atoi(argv[0]);
#else
  return puts(argv[0]);
#endif
}
