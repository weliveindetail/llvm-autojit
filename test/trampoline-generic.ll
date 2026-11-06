; RUN: env AUTOJIT_STATIC_THRESHOLD=0 %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S %s -o - | FileCheck %s

; ModuleID = '/workspace/llvm-autojit/test/trampoline.ll'
source_filename = "/workspace/llvm-autojit/test/trampoline-generic.cpp"
target triple = "riscv64-unknown-linux-gnu"

; Descriptor of the lazy module with its path
; CHECK: @__llvm_autojit_module = private constant { i32, i32, i64, [0 x i32], [0 x i8], [49 x i8] } { i32 2, i32 0, i64 {{-?[0-9]+}}, {{.*}}, [49 x i8] c"/tmp/autojit_c7193c4eafd0b9e41c8c01e4eb6ec13e.bc\00" }

; Pointer to lazy function materialization
; CHECK: @__llvm_autojit_ptr__Z3addii = internal global ptr null

; Functions are reduced to static frames that call into the runtime. This is
; the generic trampoline for targets without a specific one.
; CHECK: define {{.*}} i32 @_Z3addii{{.*}}
;
; CHECK:   load atomic ptr, ptr @__llvm_autojit_ptr__Z3addii acquire
; CHECK:   icmp eq ptr %{{.*}}, null
; CHECK:   br
;
; CHECK-NOT: store
; CHECK:   call ptr @__llvm_autojit_materialize(ptr @__llvm_autojit_ptr__Z3addii, i64 {{-?[0-9]+}}, ptr @__llvm_autojit_module)
; CHECK:   br
;
; CHECK:   tail call noundef i32 %impl_ptr(i32 noundef %0, i32 noundef %1)
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
; CHECK: declare ptr @__llvm_autojit_materialize(ptr, i64, ptr)

; Modules are loaded on demand, there is no registration at startup
; CHECK-NOT: @llvm.global_ctors

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{!"Ubuntu clang version 20.1.8 (++20250708083436+6fb913d3e2ec-1~exp1~20250708203453.133)"}
