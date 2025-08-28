// Minimal executable test that uses libautojit-runtime.so
//
// RUN: %clang -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang %t.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic -o %t.exe
// RUN: %t.exe 2>&1 | FileCheck %s

// CHECK: AutoJIT Runtime Test
// CHECK: Hello from AutoJIT!
// CHECK: add(5, 3) = 8
// CHECK: multiply(4, 6) = 24
// CHECK: Test completed

#include <iostream>

void print_hello() {
    std::cout << "Hello from AutoJIT!\n";
}

int add(int A, int B) {
    return A + B;
}

int multiply(int X, int Y) {
    int Result = 1;
    for (int I = 0; I < Y; ++I) {
        Result += X;
    }
    return Result - 1;
}

int main() {
    std::cout << "AutoJIT Runtime Test\n";

    // These function calls will trigger __llvm_autojit_materialize
    int Sum = add(5, 3);
    int Product = multiply(4, 6);
    print_hello();

    std::cout << "add(5, 3) = " << Sum << "\n";
    std::cout << "multiply(4, 6) = " << Product << "\n";
    std::cout << "Test completed\n";

    return 0;
}
