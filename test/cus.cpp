// Check that we can use multiple compile-units
//
// RUN: %clang -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/add.cpp -o %t_add.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/hello.cpp -o %t_hello.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/multiply.cpp -o %t_multiply.o
//
// RUN: %clang -o %t_1.exe %t_add.o %t_multiply.o %t_hello.o %t.o \
// RUN:        -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_1.exe 2>&1 | FileCheck %s
//
// RUN: %clang -o %t_2.exe %t_add.o %t_multiply.o %t_hello.o -fpass-plugin=%autojit_plugin %s \
// RUN:        -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_2.exe 2>&1 | FileCheck %s

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
