int Counter = 0;

// Above the threshold for small leaf functions
int increment(void) {
  int Old = Counter;
  for (int I = 0; I < 1; I += 1)
    Old += 1;
  Counter = Old;
  return Counter;
}
