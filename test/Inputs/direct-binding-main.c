#include <stdio.h>

int outer(void);

int main(void) {
  printf("outer: %d\n", outer());
  return 0;
}
