// Check that lazy and static code use the same global variables
//
// RUN: %clang %s -fpass-plugin=%autojit_plugin -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe 2>&1 | FileCheck %s
//
// RUN: %clang %s -fpass-plugin=%autojit_plugin -rdynamic -L%autojit_runtime_dir -Wl,--whole-archive -lautojit_static-%arch -Wl,--no-whole-archive %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK-NOT: JIT session error
//
// CHECK: SimpleGV static = [[ADDR1:[0-9a-f]+]]
// CHECK: DumperGV static = [[ADDR2:[0-9a-f]+]]
// CHECK: SimpleGV lazy = [[ADDR1]]
// CHECK: DumperGV lazy = [[ADDR2]]

#include <cstdint>
#include <cstdio>

int SimpleGV = 42;

// Static initializer is in static code
struct DumpSimpleGVStaticAddr {
  DumpSimpleGVStaticAddr() {
    printf("SimpleGV static = %lx\n", reinterpret_cast<uintptr_t>(&SimpleGV));
    printf("DumperGV static = %lx\n", reinterpret_cast<uintptr_t>(this));
  }
};

static DumpSimpleGVStaticAddr DumperGV;

// Function body is JITed
int main() {
  printf("SimpleGV lazy = %lx\n", reinterpret_cast<uintptr_t>(&SimpleGV));
  printf("DumperGV lazy = %lx\n", reinterpret_cast<uintptr_t>(&DumperGV));
  return 0;
}
