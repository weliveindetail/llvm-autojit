#include <arm_neon.h>

// Homogeneous floating-point aggregate: passed in d0-d3
struct Quad {
  double A, B, C, D;
};

// Returned indirectly through the address in x8
struct Big {
  long A, B, C, D, E;
};

float64x2_t addVectors(float64x2_t A, float64x2_t B);
double sumHFA(Quad Q);
Big makeBig(long Base);
long sumIntegers(long A, long B, long C, long D, long E, long F, long G,
                 long H, long I, long J);
double sumDoubles(double A, double B, double C, double D, double E, double F,
                  double G, double H, double I, double J);
double sumVarargs(int N, ...);
