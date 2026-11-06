#include <signal.h>

volatile sig_atomic_t Signals = 0;

// Above the threshold for small leaf functions
void handler(int Sig) {
  int Unused = 0;
  for (int I = 0; I < Sig; I += 1)
    Unused += I * Sig + 1;
  Signals = Unused > 0 ? Signals + 1 : Signals + 1;
}

int work(int X) {
  int Sum = 0;
  for (int I = 0; I < 3; I += 1)
    Sum += X;
  return Sum;
}
