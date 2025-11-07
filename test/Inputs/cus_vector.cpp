#include <cstdint>
#include <vector>

static std::vector<uint64_t> Fibonaccis = {0};

uint64_t next_fibbonacci() {
  auto It = Fibonaccis.rbegin();
  uint64_t Last = *It;
  uint64_t Previous = (++It == Fibonaccis.rend()) ? 1 : *It;
  Fibonaccis.push_back(Last + Previous);
  return Fibonaccis.back();
}
