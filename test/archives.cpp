// Check that we can use archives. The definitions in the archive are only
// referenced from lazy code. The import table in the static object keeps the
// references, so the linker extracts them anyway.
//
// RUN: %clang -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/add.cpp -o %t_add.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/hello.cpp -o %t_hello.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/multiply.cpp -o %t_multiply.o
// RUN: rm -f %t.a
// RUN: %ar cq %t.a %t_add.o %t_multiply.o %t_hello.o
//
// RUN: %clang %t.o %t.a -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe 2>&1 | FileCheck %s
//
// Imports don't depend on dynamic symbols
// RUN: %clang %t.o %t.a -Wl,--gc-sections -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess_gc.exe
// RUN: %t_inprocess_gc.exe 2>&1 | FileCheck %s
//
// RUN: %clang %t.o %t.a -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe 2>&1 | FileCheck %s

// CHECK-NOT: JIT session error

// CHECK: AutoJIT Runtime Test
// CHECK: Hello from AutoJIT!
// CHECK: add(5, 3) = 8
// CHECK: multiply(4, 6) = 24
// CHECK: Test completed

#include <iostream>

// In separate translation units: their lazy modules are loaded on demand
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
