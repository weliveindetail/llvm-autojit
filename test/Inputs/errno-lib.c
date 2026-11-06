int helper(int X) {
  int Sum = 0;
  for (int I = 0; I < X; I += 1)
    Sum += I * X;
  return Sum;
}

// Varargs use the generic trampoline on AArch64
int otherHelper(int X, ...) {
  int Sum = 0;
  for (int I = 0; I < X; I += 1)
    Sum += I * X + 1;
  return Sum;
}
