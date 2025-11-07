// Check that we mix and match regular compile-units with autojit ones
//
// RUN: %clang -c %s -o %t_main_regular.o
// RUN: %clang -c %s -o %t_main_autojit.o -fpass-plugin=%autojit_plugin
//
// RUN: %clang -c %S/Inputs/cus_vector.cpp -o %t_vector_regular.o
// RUN: %clang -c %S/Inputs/cus_vector.cpp -o %t_vector_autojit.o -fpass-plugin=%autojit_plugin
//
// RUN: %clang -c %S/Inputs/cus_string.cpp -o %t_string_regular.o
// RUN: %clang -c %S/Inputs/cus_string.cpp -o %t_string_autojit.o -fpass-plugin=%autojit_plugin
//
// RUN: %clang -o %t_1.exe %t_main_regular.o %t_string_regular.o %t_vector_regular.o -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_1.exe | FileCheck %s
//
// RUN: %clang -o %t_2.exe %t_main_regular.o %t_string_regular.o %t_vector_autojit.o -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_2.exe | FileCheck %s
//
// RUN: %clang -o %t_3.exe %t_main_regular.o %t_string_autojit.o %t_vector_autojit.o -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_3.exe | FileCheck %s
//
// RUN: %clang -o %t_4.exe %t_main_autojit.o %t_string_autojit.o %t_vector_autojit.o -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_4.exe | FileCheck %s
//
// RUN: %clang -o %t_5.exe %t_main_autojit.o %t_string_autojit.o %t_vector_regular.o -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_5.exe | FileCheck %s
//
// RUN: %clang -o %t_6.exe %t_main_autojit.o %t_string_regular.o %t_vector_regular.o -lautojit-runtime -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir
// RUN: %t_6.exe | FileCheck %s

// CHECK: Test completed

#include <iostream>
#include <cstdint>

// All translation units register their lazy module at startup
uint64_t next_fibbonacci();
const char *format_fibonacci(uint64_t);

int main() {
    std::cout << format_fibonacci(next_fibbonacci()) << "\n";
    std::cout << format_fibonacci(next_fibbonacci()) << "\n";
    std::cout << format_fibonacci(next_fibbonacci()) << "\n";
    std::cout << format_fibonacci(next_fibbonacci()) << "\n";
    std::cout << format_fibonacci(next_fibbonacci()) << "\n";
    std::cout << "Test completed\n";
    return 0;
}
