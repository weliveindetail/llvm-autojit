// Check that we can use archives
// TODO: Get away without `-Wl,--whole-archive`?
//
// RUN: %clang -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/add.cpp -o %t_add.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/hello.cpp -o %t_hello.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/multiply.cpp -o %t_multiply.o
// RUN: rm -f %t_lib.a
// RUN: %ar cq %t_lib.a %t_add.o %t_multiply.o %t_hello.o
// RUN: %clang %t.o -Wl,--whole-archive %t_lib.a -Wl,--no-whole-archive -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic -o %t_lib.exe
// RUN: env AUTOJIT_DEBUG=On %t_lib.exe 2>&1 | FileCheck %s

// CHECK: Registering module /tmp/autojit_
// CHECK: Registering module /tmp/autojit_
// CHECK: Registering module /tmp/autojit_
// CHECK: Registering module /tmp/autojit_
// CHECK: AutoJIT Runtime Test
// CHECK: Hello from AutoJIT!
// CHECK: add(5, 3) = 8
// CHECK: multiply(4, 6) = 24
// CHECK: Test completed

#include <iostream>

// In separate translation units: they must register their lazy module at startup
int add(int, int);
int multiply(int, int);
void hello();

int main() {
    std::cout << "AutoJIT Runtime Test\n";

    int Sum = add(5, 3);
    int Product = multiply(4, 6);
    hello();

    std::cout << "add(5, 3) = " << Sum << "\n";
    std::cout << "multiply(4, 6) = " << Product << "\n";
    std::cout << "Test completed\n";

    return 0;
}
