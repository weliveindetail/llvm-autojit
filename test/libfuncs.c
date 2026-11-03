// Programs can define library functions themselves. The executable exports
// them, because the C library defines them as well, so they interpose the ones
// in the C library. The runtime calls them too, so they must stay in static
// code. Otherwise the runtime would call lazy code while it materializes lazy
// code.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin -O0 -S -emit-llvm %s -o - | FileCheck --check-prefix=IR %s
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// IR-NOT: @__llvm_autojit_ptr_strlen
// IR: @__llvm_autojit_ptr_main
//
// CHECK: strlen("autojit") = 7

#include <stddef.h>
#include <stdio.h>

size_t strlen(const char *Str) {
  size_t Len = 0;
  while (Str[Len])
    Len += 1;
  return Len;
}

int main() {
  printf("strlen(\"autojit\") = %zu\n", strlen("autojit"));
  return 0;
}
