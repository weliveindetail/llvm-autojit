// RUN: %clang -fpass-plugin=%autojit_plugin -O0 -S -emit-llvm %s -o - 2>&1 | FileCheck %s

// Test that the AutoJIT pass runs

// Path to lazy module
// CHECK: @__llvm_autojit_file_path = private unnamed_addr constant [49 x i8] c"/tmp/autojit_7cbf95157f77aa3acf3d3653fb89d070.bc\00"

// Pointer to lazy function materialization
// CHECK: @__autojit_ptr__Z3addii = internal global ptr null
// CHECK: private unnamed_addr constant [9 x i8] c"_Z3addii\00"

// Static function frames contain calls to runtime function
// CHECK: define {{.*}} i32 @_Z3addii{{.*}}
//
// CHECK:   load ptr, ptr @__autojit_ptr__Z3addii
// CHECK:   icmp eq ptr %{{.*}}, null
// CHECK:   br
//
// CHECK:   call void @__llvm_autojit_materialize
// CHECK:   load ptr, ptr @__autojit_ptr__Z3addii
// CHECK:   br
//
// CHECK:   tail call i32
// CHECK:   ret i32
//
int add(int A, int B) { return A + B; }

// Return types are respected
// CHECK: define {{.*}} void @_Z4dumpv
// CHECK: tail call void
// CHECK: ret void
//
const char *Banner = "Hello autojit";
extern int printf(const char *, ...);
void dump() { printf(Banner); }

// Declaration of runtime function
// CHECK: declare void @__llvm_autojit_materialize(ptr, ptr, ptr)
