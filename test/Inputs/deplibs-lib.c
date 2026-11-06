#include <stdarg.h>
#include <stdio.h>

// The first lazy call in the process comes in with arguments in registers
double first(int I, double D, const char *S, float F) {
  printf("ctor: %d %.1f %s %.2f\n", I, D, S, F);
  return D;
}

// Varargs use the generic trampoline on AArch64
int vsum(int N, ...) {
  va_list Args;
  va_start(Args, N);
  int Sum = 0;
  for (int I = 0; I < N; I += 1)
    Sum += va_arg(Args, int);
  va_end(Args);
  return Sum;
}
