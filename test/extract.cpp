// RUN: %clang -fpass-plugin=%autojit_plugin -O0 -S -emit-llvm %s -o - 2>&1 | FileCheck %s

// Test that the AutoJIT pass runs

// Path to lazy module
// CHECK: @__llvm_autojit_lazy_file = private unnamed_addr constant [49 x i8] c"/tmp/autojit_7cbf95157f77aa3acf3d3653fb89d070.bc\00"

// Pointer to lazy function materialization
// CHECK: @__autojit_ptr__Z3addii = internal global ptr null

// Static function frames contain calls to runtime function
// CHECK: define {{.*}} i32 @_Z3addii{{.*}}
//
// CHECK:   load ptr, ptr @__autojit_ptr_
// CHECK:   icmp eq ptr %{{.*}}, null
// CHECK:   br
//
// CHECK:   store {{.*}} 5596766123435450959 to {{.*}} @__autojit_ptr__Z3addii
// CHECK:   call void @__llvm_autojit_materialize
// CHECK:   load ptr, ptr @__autojit_ptr_
// CHECK:   br
//
// CHECK:   tail call i32
// CHECK:   ret i32
//
int add(int A, int B) { return A + B; }

// Declaration of runtime functions
// CHECK: declare void @__llvm_autojit_materialize(ptr)
// CHECK: declare void @__llvm_autojit_register(ptr)
