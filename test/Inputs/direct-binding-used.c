#include <stdio.h>

__attribute__((used)) static int first(int X) { return X + 1; }
int (*const volatile FirstPtr)(int) = first;

static int (*SecondPtr)(int) = first;
__attribute__((used)) static int second(int X) { return SecondPtr(X) + 1; }
int (*const volatile SecondCaller)(int) = second;

int main(void) {
  printf("used: %d\n", SecondCaller(1));
  return 0;
}
