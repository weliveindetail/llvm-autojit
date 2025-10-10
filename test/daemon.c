// Exercise the daemonized runtime with static stub library
// XFAIL: *

// RUN: %clang -fpass-plugin=%autojit_plugin -xc -c %s -o %t.o
// RUN: %clang %t.o -L%autojit_runtime_dir -Wl,--whole-archive -lautojit_static-%arch -Wl,--no-whole-archive -rdynamic -pthread -o %t.exe
// RUN: env AUTOJIT_DAEMON_PATH=%autojit_tools_dir/autojitd %t.exe 2>&1 | FileCheck %s

// CHECK: AutoJIT Daemon Test
// CHECK: add(10, 20) = 30
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

int main(void) {
    printf("AutoJIT Daemon Test\n");

    // These function calls will trigger daemon initialization and materialization
    int sum = add(10, 20);
    int fact = factorial(5);

    printf("add(10, 20) = %d\n", sum);
    printf("factorial(5) = %d\n", fact);
    printf("Test completed successfully\n");

    return 0;
}
