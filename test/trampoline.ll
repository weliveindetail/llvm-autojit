; RUN: %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S %s -o - | FileCheck %s

; ModuleID = '/workspace/llvm-autojit/test/trampoline.ll'
source_filename = "/workspace/llvm-autojit/test/trampoline.cpp"
target triple = "x86_64-pc-linux-gnu"

; Pointer to lazy function materialization
; CHECK: @__llvm_autojit_ptr__Z3addii = internal global ptr null

; Path to lazy module
; CHECK: @__llvm_autojit_lazy_file = private unnamed_addr constant [49 x i8] c"/tmp/autojit_e897fd8886de1380cf0e7d06010251b0.bc\00"

; Functions are reduced to static frames that call into the runtime
; CHECK: define {{.*}} i32 @_Z3addii{{.*}}
;
; CHECK:   load ptr, ptr @__llvm_autojit_ptr_
; CHECK:   icmp eq ptr %{{.*}}, null
; CHECK:   br
;
; CHECK:   store {{.*}} -6721289519639444558 to {{.*}} @__llvm_autojit_ptr__Z3addii
; CHECK:   call void @__llvm_autojit_materialize
; CHECK:   load ptr, ptr @__llvm_autojit_ptr_
; CHECK:   br
;
; CHECK:   tail call i32
; CHECK:   ret i32
;
define noundef i32 @_Z3addii(i32 noundef %0, i32 noundef %1) noinline optnone uwtable {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store i32 %1, ptr %4, align 4
  %5 = load i32, ptr %3, align 4
  %6 = load i32, ptr %4, align 4
  %7 = add nsw i32 %5, %6
  ret i32 %7
}

; Declarations of relevant runtime functions exist
; CHECK: declare void @__llvm_autojit_materialize(ptr)
; CHECK: declare void @__llvm_autojit_register(ptr)

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{!"Ubuntu clang version 20.1.8 (++20250708083436+6fb913d3e2ec-1~exp1~20250708203453.133)"}
