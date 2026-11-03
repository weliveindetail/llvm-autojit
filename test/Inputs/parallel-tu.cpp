// Compiled once per TU with -DTU=<index>
#include "parallel.h"

#include <atomic>

#define CAT2(A, B) A##B
#define CAT(A, B) CAT2(A, B)
#define COMPUTE CAT(compute, TU)

// Local state, shared between static and lazy code
static std::atomic<unsigned> Calls{0};

static unsigned localHelper(unsigned X) {
  std::string Str = "tu" + std::to_string(TU) + ":" + std::to_string(X);
  return hashString(Str) ^ mix<TU>(X);
}

unsigned COMPUTE(unsigned X, int Depth) {
  Calls.fetch_add(1, std::memory_order_relaxed);
  Accumulator Acc;
  for (unsigned I = 0; I < 4; I += 1)
    Acc.add(localHelper(X + I));
  unsigned Result = Acc.sum();
  if (Depth > 0)
    Result ^= ComputeFns[(TU + 1) % NUM_TUS](Result, Depth - 1);
  return Result;
}
