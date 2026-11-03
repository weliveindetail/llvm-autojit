// Check that the runtime doesn't reuse a cached object after the plugin wrote
// a new lazy module for the same source file, but reuses it otherwise.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_v1.exe
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t_v1.exe | FileCheck --check-prefix=V1 %s
// RUN: %clang_c -fpass-plugin=%autojit_plugin -DV2 %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_v2.exe
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t_v2.exe | FileCheck --check-prefix=V2 %s
//
// Second run loads the cached object
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t_v2.exe | FileCheck --check-prefix=V2 %s
//
// V1: Version 1
// V2: Version 2

#include <stdio.h>

int main() {
#ifdef V2
  puts("Version 2");
#else
  puts("Version 1");
#endif
  return 0;
}
