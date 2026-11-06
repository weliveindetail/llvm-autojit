// Symbol versions come from module-level inline assembly. It refers to the
// original function name, that doesn't exist in lazy modules.
//
// REQUIRES: lld
// RUN: %clang_c -fpass-plugin=%autojit_plugin -fuse-ld=lld -Wl,--no-dependent-libraries -O0 %s -Wl,--version-script=%S/Inputs/symver.map -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.exe
// RUN: %t.exe | FileCheck %s
//
// CHECK: versioned 42

#include <stdio.h>

__asm__(".symver versioned_impl, versioned@@V1");

int versioned_impl(void) { return 42; }

int main() {
  printf("versioned %d\n", versioned_impl());
  return 0;
}
