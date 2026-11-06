// Check that the AArch64 resolver preserves all registers that carry
// arguments while it materializes a function: vector and floating-point
// registers q0-q7, integer registers x0-x7, the indirect result register x8,
// stack arguments and varargs. The runtime clobbers v0-v7 explicitly during
// materialization, because the code it runs might not touch them.
//
// REQUIRES: aarch64
// RUN: %clang -fpass-plugin=%autojit_plugin -I%S/Inputs -c %S/Inputs/resolver-aarch64-callees.cpp -o %t_callees.o
// RUN: %clang -fpass-plugin=%autojit_plugin -I%S/Inputs -c %s -o %t.o
// RUN: llvm-objdump -d %t_callees.o | FileCheck --check-prefix=LEAN %s
// RUN: %clang %t.o %t_callees.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: env AUTOJIT_TEST_CLOBBER_VECTOR_REGS=1 %t_inprocess.exe | FileCheck %s
// RUN: %clang %t.o %t_callees.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: env AUTOJIT_TEST_CLOBBER_VECTOR_REGS=1 %t_remote.exe | FileCheck %s
//
// Callees use lean trampolines that don't call into the runtime directly
// LEAN-LABEL: <__llvm_autojit_resolve_thunk>:
// LEAN-NEXT:    adrp x17,
// LEAN-NEXT:    ldr x17, [x17]
// LEAN-NEXT:    br x17
// LEAN-LABEL: <_Z10addVectors13__Float64x2_tS_>:
// LEAN-NEXT:    adr x16,
// LEAN-NEXT:    adrp x17,
// LEAN-NEXT:    add x17, x17,
// LEAN-NEXT:    ldar x17, [x17]
// LEAN-NEXT:    br x17
//
// CHECK: vector: 11 22
// CHECK: hfa: 10
// CHECK: big: 5 6 7 8 9
// CHECK: integers: 55
// CHECK: doubles: 55.5
// CHECK: varargs: 15.5

#include <cstdio>

#include "resolver-aarch64.h"

int main() {
  float64x2_t A = {1, 2};
  float64x2_t B = {10, 20};
  float64x2_t V = addVectors(A, B);
  printf("vector: %g %g\n", vgetq_lane_f64(V, 0), vgetq_lane_f64(V, 1));
  printf("hfa: %g\n", sumHFA({1, 2, 3, 4}));
  Big R = makeBig(5);
  printf("big: %ld %ld %ld %ld %ld\n", R.A, R.B, R.C, R.D, R.E);
  printf("integers: %ld\n", sumIntegers(1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
  printf("doubles: %g\n", sumDoubles(1, 2, 3, 4, 5, 6, 7, 8, 9, 10.5));
  printf("varargs: %g\n", sumVarargs(5, 1.5, 2.0, 3.0, 4.0, 5.0));
  return 0;
}
