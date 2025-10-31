// Check that function pointers don't break in lazy code
//
// RUN: %clang %s -rdynamic -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %clang %s -rdynamic -fpass-plugin=%autojit_plugin -L%autojit_runtime_dir -Wl,--whole-archive -lautojit_static-%arch -Wl,--no-whole-archive %fsanitize -o %t_remote.exe
// RUN: %t_inprocess.exe 2>&1 | FileCheck %s
// RUN: %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK-NOT: JIT session error
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
