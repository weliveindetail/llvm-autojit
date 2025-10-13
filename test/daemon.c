// Exercise the daemonized runtime with static stub library
// XFAIL: orc_rt

// RUN: %clang -fpass-plugin=%autojit_plugin -xc -c %s -o %t.o
// RUN: %clang %t.o -L%autojit_runtime_dir -lautojit_static-%arch -rdynamic -pthread -o %t.exe
// RUN: env AUTOJIT_DAEMON_PATH=%autojit_tools_dir/autojitd %t.exe 2>&1 | FileCheck %s

// CHECK: AutoJIT Daemon Test
// CHECK: add(1, 4) = 5
// CHECK: factorial(5) = 120
// CHECK: Test completed successfully

#include <stdio.h>

int add(int a, int b) {
  return a + b;
}

int factorial(int n) {
  if (n <= 1)
    return 1;
  return n * factorial(n - 1);
}

int main(int argc, char *argv[]) {
  printf("AutoJIT Daemon Test\n");

  // These function calls will trigger daemon initialization and materialization
  int sum = add(argc, 4);
  int fact = factorial(sum);

  printf("add(%d, 4) = %d\n", argc, sum);
  printf("factorial(%d) = %d\n", sum, fact);
  printf("Test completed successfully\n");

  return 0;
}
