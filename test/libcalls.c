// The backend calls compiler helpers on its own, so they aren't in import
// tables. JITed code must find them in both modes.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: int128: 1024 5
// CHECK: float128: 8.750
// CHECK: complex: -5.0 10.0

#include <complex.h>
#include <stdio.h>

__int128 divide(__int128 A, __int128 B) { return A / B; }
unsigned __int128 mod(unsigned __int128 A, unsigned __int128 B) { return A % B; }
double complex multiply(double complex A, double complex B) { return A * B; }

// On AArch64 this is long double, on x86-64 it stays in x87 and doesn't call
#if defined(__aarch64__)
long double fp(long double A, long double B) { return A * B + A / B; }
#else
__float128 fp(__float128 A, __float128 B) { return A * B + A / B; }
#endif

int main(void) {
  printf("int128: %lld %lld\n", (long long)divide((__int128)1 << 100, (__int128)1 << 90),
         (long long)mod(((unsigned __int128)1 << 100) + 5, (unsigned __int128)1 << 70));
  printf("float128: %.3f\n", (double)fp(3.5, 2.0));
  double complex R = multiply(1 + 2 * I, 3 + 4 * I);
  printf("complex: %.1f %.1f\n", creal(R), cimag(R));
  return 0;
}
