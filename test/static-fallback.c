// Code that can't run in the JIT stays in static code, instead of failing at run
// time.
//
// RUN: %clang_c -O0 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c -O0 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
// RUN: %clang_c -O2 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_opt.exe
// RUN: %t_opt.exe | FileCheck %s
//
// configure scripts rely on errors from the backend for invalid inline asm
// RUN: not %clang_c -fpass-plugin=%autojit_plugin -DINVALID_ASM -c %s -o %t_invalid.o 2>&1 | FileCheck --check-prefix=INVALID %s
// INVALID: error: {{.*}}instruction
//
// CHECK: inline asm: 5
// CHECK: computed goto: 1 2
// CHECK: const table: 1 2
// CHECK: ifunc: 6
// CHECK: weak alias: 2
// CHECK: module asm: 3
// CHECK: asm global: 42

#include <stdio.h>

// The table holds label addresses of the static function
int computedGoto(int I) {
  static void *Table[] = {&&A, &&B};
  goto *Table[I];
A:
  return 1;
B:
  return 2;
}

int constTable(int I) {
  static void *const Table[] = {&&A, &&B};
  goto *Table[I];
A:
  return 1;
B:
  return 2;
}

// The dynamic linker calls the resolver during relocation
static int impl(int X) { return X * 3; }
static void *resolver(void) { return impl; }
int dispatch(int X) __attribute__((ifunc("resolver")));

int real(int X) { return X + 1; }
__attribute__((weak)) int weakAlias(int X) __attribute__((alias("real")));

// Defined in the static object, repeating it in the lazy module would clash
#if defined(__aarch64__)
__asm__(".text\n.globl asmTwo\n.type asmTwo,%function\nasmTwo:\nmov w0,#2\nret\n");
#define LOAD_GOT(R, S) "adrp %" #R ",:got:" S "\nldr %" #R ",[%" #R ",:got_lo12:" S "]"
#else
__asm__(".text\n.globl asmTwo\n.type asmTwo,@function\nasmTwo:\nmovl $2,%eax\nret\n");
#define LOAD_GOT(R, S) "movq " S "@GOTPCREL(%%rip),%" #R
#endif
extern int asmTwo(void);
int callAsm(void) { return asmTwo() + 1; }

// The asm text names the symbol, so it only links in the static object
int Global = 41;
int asmGlobal(void) {
  int *P;
  __asm__(LOAD_GOT(0, "Global") : "=r"(P));
  return *P + 1;
}

#ifdef INVALID_ASM
int invalidAsm(void) {
  __asm__("definitely_not_an_instruction");
  return 0;
}
#endif

// Stays static and its comdat must not end up on the import in the lazy module
inline __attribute__((weak)) int inlineAsm(int X) {
  __asm__("");
  __asm__("nop");
  return X;
}

int main(void) {
  printf("inline asm: %d\n", inlineAsm(5));
  printf("computed goto: %d %d\n", computedGoto(0), computedGoto(1));
  printf("const table: %d %d\n", constTable(0), constTable(1));
  printf("ifunc: %d\n", dispatch(2));
  printf("weak alias: %d\n", weakAlias(1));
  printf("module asm: %d\n", callAsm());
  printf("asm global: %d\n", asmGlobal());
  return 0;
}
