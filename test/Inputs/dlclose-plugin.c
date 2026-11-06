int Counter = 0;

int plugin(void) {
  for (int I = 0; I < 1; I += 1)
    Counter += 1;
  return Counter;
}
