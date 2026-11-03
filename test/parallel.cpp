// Stress test for parallel materialization: many threads make their first
// calls into many lazy modules at the same time. Each lazy module calls into
// the next one, they share inline functions and use the C++ standard library.
// The output must match a build without the plugin.
//
// RUN: rm -rf %t && mkdir -p %t
// RUN: for I in $(seq 0 19); do cp %S/Inputs/parallel-tu.cpp %t/tu$I.cpp; done
// RUN: for I in $(seq 0 19); do %clang -I%S/Inputs -DTU=$I -c %t/tu$I.cpp -o %t/tu$I.plain.o; done
// RUN: for I in $(seq 0 19); do %clang -I%S/Inputs -DTU=$I -fpass-plugin=%autojit_plugin -c %t/tu$I.cpp -o %t/tu$I.autojit.o; done
// RUN: %clang -I%S/Inputs -c %s -o %t/main.plain.o
// RUN: %clang -I%S/Inputs -fpass-plugin=%autojit_plugin -c %s -o %t/main.autojit.o
//
// RUN: %clang %t/main.plain.o %t/tu*.plain.o -pthread -o %t/plain.exe
// RUN: %t/plain.exe > %t/expected.txt
// RUN: FileCheck %s < %t/expected.txt
//
// RUN: %clang %t/main.autojit.o %t/tu*.autojit.o -pthread -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t/inprocess.exe
// RUN: for I in 1 2 3 4 5; do %t/inprocess.exe > %t/inprocess.txt && diff %t/expected.txt %t/inprocess.txt || exit 1; done
//
// RUN: %clang %t/main.autojit.o %t/tu*.autojit.o -pthread -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t/remote.exe
// RUN: for I in 1 2 3; do %t/remote.exe > %t/remote.txt && diff %t/expected.txt %t/remote.txt || exit 1; done
//
// CHECK: thread 0:
// CHECK: thread 15:
// CHECK: serial: 00000000

#include "parallel.h"

#include <atomic>
#include <cstdio>
#include <thread>

#define ENTRY(I) compute##I,
const ComputeFn ComputeFns[NUM_TUS] = {
    ENTRY(0) ENTRY(1) ENTRY(2) ENTRY(3) ENTRY(4) ENTRY(5) ENTRY(6) ENTRY(7)
    ENTRY(8) ENTRY(9) ENTRY(10) ENTRY(11) ENTRY(12) ENTRY(13) ENTRY(14)
    ENTRY(15) ENTRY(16) ENTRY(17) ENTRY(18) ENTRY(19)};
#undef ENTRY

constexpr int NumThreads = 16;
constexpr int NumIterations = 50;

static unsigned run(int Thread) {
  // First call: a chain through all lazy modules, starting at a different one
  // in each thread
  unsigned Result = ComputeFns[Thread % NUM_TUS](Thread, NUM_TUS);
  for (int I = 0; I < NumIterations; I += 1)
    Result ^= ComputeFns[mix<3>(Result + I) % NUM_TUS](Result + I, I % 3);
  return Result;
}

int main() {
  unsigned Results[NumThreads];
  std::atomic<int> Ready{0};
  std::atomic<bool> Go{false};
  std::thread Threads[NumThreads];
  for (int T = 0; T < NumThreads; T += 1) {
    Threads[T] = std::thread([&, T] {
      Ready += 1;
      while (!Go)
        ;
      Results[T] = run(T);
    });
  }
  while (Ready < NumThreads)
    ;
  Go = true;
  for (std::thread &T : Threads)
    T.join();

  unsigned Serial = 0;
  for (int T = 0; T < NumThreads; T += 1) {
    printf("thread %d: %08x\n", T, Results[T]);
    Serial ^= run(T) ^ Results[T];
  }
  // All bits cancel out if serial and parallel runs agree
  printf("serial: %08x\n", Serial);
  return 0;
}
