// Exercise the daemonized runtime with static stub library

// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang_c %t.o %fsanitize -L%autojit_runtime_dir -lautojit_static-%arch -pthread -o %t.exe
// RUN: env AUTOJITD_FULL_SHUTDOWN=Off %t.exe 2>&1 | FileCheck %s
// RUN: env AUTOJITD_FULL_SHUTDOWN=On %t.exe 2>&1 | FileCheck %s

// The stub library can come before the objects on the link line
// RUN: %clang_c -L%autojit_runtime_dir -lautojit_static-%arch %t.o %fsanitize -pthread -o %t_lib_first.exe
// RUN: %t_lib_first.exe 2>&1 | FileCheck %s

// Stub with debugger support
// RUN: %clang_c %t.o %fsanitize -L%autojit_runtime_dir -lautojit_static_debug-%arch -pthread -o %t_debug.exe
// RUN: %t_debug.exe 2>&1 | FileCheck %s

// CHECK-NOT: JIT session error

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
