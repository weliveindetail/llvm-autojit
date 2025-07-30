// Check that lazy and static code uses the same global variables
//
// RUN: %clang %s -o %t.exe -fpass-plugin=%autojit_plugin \
// RUN:        -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic
// RUN: env AUTOJIT_DEBUG=On %t.exe | FileCheck %s
//
// CHECK: SimpleGV static = [[ADDR1:[0-9a-f]+]]
// CHECK: DumperGV static = [[ADDR2:[0-9a-f]+]]
// CHECK: SimpleGV lazy = [[ADDR1]]
// CHECK: DumperGV lazy = [[ADDR2]]

#include <cstdint>
#include <cstdio>

int SimpleGV = 42;

struct DumpSimpleGVStaticAddr {
  DumpSimpleGVStaticAddr() {
    printf("SimpleGV static = %lx\n", reinterpret_cast<uintptr_t>(&SimpleGV));
    printf("DumperGV static = %lx\n", reinterpret_cast<uintptr_t>(this));
  }
};

static DumpSimpleGVStaticAddr DumperGV;

int main() {
  printf("SimpleGV lazy = %lx\n", reinterpret_cast<uintptr_t>(&SimpleGV));
  printf("DumperGV lazy = %lx\n", reinterpret_cast<uintptr_t>(&DumperGV));
  return 0;
}
