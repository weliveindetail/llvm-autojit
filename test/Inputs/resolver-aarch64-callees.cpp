// The first call into this module materializes it as a whole
#include <arm_neon.h>
#include <cstdarg>

#include "resolver-aarch64.h"

float64x2_t addVectors(float64x2_t A, float64x2_t B) { return vaddq_f64(A, B); }

double sumHFA(Quad Q) { return Q.A + Q.B + Q.C + Q.D; }

Big makeBig(long Base) { return {Base, Base + 1, Base + 2, Base + 3, Base + 4}; }

long sumIntegers(long A, long B, long C, long D, long E, long F, long G,
                 long H, long I, long J) {
  return A + B + C + D + E + F + G + H + I + J;
}

double sumDoubles(double A, double B, double C, double D, double E, double F,
                  double G, double H, double I, double J) {
  return A + B + C + D + E + F + G + H + I + J;
}

double sumVarargs(int N, ...) {
  va_list Args;
  va_start(Args, N);
  double Sum = 0;
  for (int I = 0; I < N; I += 1)
    Sum += va_arg(Args, double);
  va_end(Args);
  return Sum;
}
