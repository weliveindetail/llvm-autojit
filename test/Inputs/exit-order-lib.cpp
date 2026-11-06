// Loops make them big enough to stay lazy
int firstAtExit(int X) {
  int Sum = 0;
  for (int I = 1; I <= X; I += 1)
    Sum += 1;
  return Sum;
}

int firstInDtor(int X) {
  int Sum = 0;
  for (int I = 1; I <= X; I += 1)
    Sum += I;
  return Sum;
}

int firstInFini(int X) {
  int Sum = 0;
  for (int I = 1; I <= X; I += 1)
    Sum += I;
  return Sum;
}
