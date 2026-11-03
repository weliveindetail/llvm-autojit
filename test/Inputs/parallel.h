#pragma once

#include <string>
#include <vector>

#define NUM_TUS 20

// Shared inline code: linkonce_odr in every TU
template <int Salt> inline unsigned mix(unsigned X) {
  X ^= X >> 13;
  X *= 0x5bd1e995u + Salt;
  return X ^ (X >> 15);
}

struct Accumulator {
  std::vector<unsigned> Values;
  void add(unsigned V) { Values.push_back(mix<1>(V)); }
  unsigned sum() const {
    unsigned S = 0;
    for (unsigned V : Values)
      S = mix<2>(S + V);
    return S;
  }
};

inline unsigned hashString(const std::string &Str) {
  unsigned H = 2166136261u;
  for (char C : Str)
    H = (H ^ static_cast<unsigned char>(C)) * 16777619u;
  return H;
}

#define DECLARE_COMPUTE(I) unsigned compute##I(unsigned X, int Depth);
DECLARE_COMPUTE(0) DECLARE_COMPUTE(1) DECLARE_COMPUTE(2) DECLARE_COMPUTE(3)
DECLARE_COMPUTE(4) DECLARE_COMPUTE(5) DECLARE_COMPUTE(6) DECLARE_COMPUTE(7)
DECLARE_COMPUTE(8) DECLARE_COMPUTE(9) DECLARE_COMPUTE(10) DECLARE_COMPUTE(11)
DECLARE_COMPUTE(12) DECLARE_COMPUTE(13) DECLARE_COMPUTE(14) DECLARE_COMPUTE(15)
DECLARE_COMPUTE(16) DECLARE_COMPUTE(17) DECLARE_COMPUTE(18) DECLARE_COMPUTE(19)
#undef DECLARE_COMPUTE

using ComputeFn = unsigned (*)(unsigned, int);
extern const ComputeFn ComputeFns[NUM_TUS];
