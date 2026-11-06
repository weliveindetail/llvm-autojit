// Check that the x86-64 resolver preserves all registers that carry arguments
// while it materializes a function: AVX vectors, integer and floating-point
// registers, stack arguments and the number of vector registers for varargs.
// The first call materializes the whole module, which runs a lot of code that
// might clobber vector registers, e.g. memcpy in the C library. Variants for
// AVX-512 don't touch the argument registers, so we clobber them explicitly.
//
// REQUIRES: x86_64, avx
// RUN: %clang -mavx -fpass-plugin=%autojit_plugin -c %S/Inputs/resolver-x86_64-callees.cpp -o %t_callees.o
// RUN: %clang -mavx -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang %t.o %t_callees.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: env AUTOJIT_TEST_CLOBBER_VECTOR_REGS=1 %t_inprocess.exe | FileCheck %s
// RUN: %clang %t.o %t_callees.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: env AUTOJIT_TEST_CLOBBER_VECTOR_REGS=1 %t_remote.exe | FileCheck %s
//
// CHECK: vector: 11 22 33 44
// CHECK: integers: 55
// CHECK: doubles: 55.5
// CHECK: varargs: 15.5

#include <cstdio>
#include <immintrin.h>

// In a separate module: their first calls materialize it
__m256d addVectors(__m256d A, __m256d B);
long sumIntegers(long A, long B, long C, long D, long E, long F, long G,
                 long H, long I, long J);
double sumDoubles(double A, double B, double C, double D, double E, double F,
                  double G, double H, double I, double J);
double sumVarargs(int N, ...);

static void testVectors() {
  __m256d A = _mm256_set_pd(4, 3, 2, 1);
  __m256d B = _mm256_set_pd(40, 30, 20, 10);
  double R[4];
  _mm256_storeu_pd(R, addVectors(A, B));
  printf("vector: %g %g %g %g\n", R[0], R[1], R[2], R[3]);
}

int main() {
  testVectors();
  printf("integers: %ld\n", sumIntegers(1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
  printf("doubles: %g\n",
         sumDoubles(1, 2, 3, 4, 5, 6, 7, 8, 9, 10.5));
  printf("varargs: %g\n", sumVarargs(5, 1.5, 2.0, 3.0, 4.0, 5.0));
  return 0;
}
