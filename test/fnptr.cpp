// Check that function pointers don't break in lazy code
//
// RUN: %clang %s -o %t.exe -fpass-plugin=%autojit_plugin \
// RUN:        -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic
// RUN: %t.exe | FileCheck %s
//
// CHECK: Address of foo static = [[ADDR:[0-9a-f]+]]
// CHECK: Address of foo lazy = [[ADDR]]

#include <cstdint>
#include <cstdio>

int foo(int x) {
  return x - 1;
}

// Static initializer is in static code
struct DumpFnPtr {
  DumpFnPtr() {
    printf("Address of foo static = %lx\n", reinterpret_cast<uintptr_t>(&foo));
  }
};

static DumpFnPtr DumperGV;

// Function body is JITed
int main(int argc, char *argv[]) {
  auto *foo_ptr = &foo;
  printf("Address of foo lazy = %lx\n", reinterpret_cast<uintptr_t>(foo_ptr));
  return foo_ptr(argc);
}
