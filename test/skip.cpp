// RUN: %clang -fpass-plugin=%autojit_plugin -O0 -S -emit-llvm %s -o - 2>&1 | FileCheck %s

// Test that the AutoJIT pass skips modules if there is nothing to lazify

// CHECK-NOT: @__llvm_autojit_ptr__Z3subi = internal global ptr null
// CHECK-NOT: @__llvm_autojit_lazy_file = private unnamed_addr constant
// CHECK-NOT: declare void @__llvm_autojit_register(ptr)
// CHECK-NOT: declare void @__llvm_autojit_materialize(ptr)
// CHECK-NOT: define internal void @_GLOBAL__sub_I_skip.cpp_llvm_autojit_init()

unsigned int RandomNumbers[] = {
   619, 720, 127, 481, 931, 816, 813, 233,
};
