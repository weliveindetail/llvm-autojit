// The first call into this module materializes it as a whole
#include <cstdarg>
#include <immintrin.h>

__m256d addVectors(__m256d A, __m256d B) {
  return _mm256_add_pd(A, B);
}

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
