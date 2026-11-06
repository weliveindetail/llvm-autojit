// Check that many threads can call lazy functions concurrently, including the
// first calls that materialize them. The functions live in different modules,
// so the runtime compiles them concurrently.
//
// RUN: %clang -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/add.cpp -o %t_add.o
// RUN: %clang -fpass-plugin=%autojit_plugin -c %S/Inputs/multiply.cpp -o %t_multiply.o
// RUN: %clang %t.o %t_add.o %t_multiply.o -pthread -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang %t.o %t_add.o %t_multiply.o -pthread -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: Sum: 3200

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

int add(int, int);
int multiply(int, int);

int main() {
  std::atomic<int> Sum = 0;
  std::atomic<bool> Go = false;
  std::vector<std::thread> Threads;
  for (int I = 0; I < 16; I += 1) {
    Threads.emplace_back([&, I] {
      while (!Go)
        ;
      Sum += (I % 2) ? add(100, 100) : multiply(10, 20);
    });
  }
  Go = true;
  for (std::thread &T : Threads)
    T.join();
  printf("Sum: %d\n", Sum.load());
  return 0;
}
