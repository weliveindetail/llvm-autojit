; REQUIRES: x86-registered-target
; RUN: %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT %s -o - | %llc -O0 -o - | FileCheck %s

; With indirect branch tracking, trampolines and the resolver thunk must start
; with exactly one endbr64. The backend inserts it for naked functions too.

source_filename = "/workspace/llvm-autojit/test/trampoline-cet.cpp"
target triple = "x86_64-pc-linux-gnu"

; CHECK-LABEL: add:
; CHECK-NEXT:  # %bb.0:
; CHECK-NEXT:    endbr64
; CHECK-NEXT:    #APP
; CHECK-NEXT:    leaq .Ltmp0(%rip), %r11
define i32 @add(i32 %0, i32 %1) {
  %3 = add i32 %0, %1
  ret i32 %3
}

; CHECK-LABEL: __llvm_autojit_resolve_thunk:
; CHECK-NEXT:  # %bb.0:
; CHECK-NEXT:    endbr64
; CHECK-NEXT:    #APP
; CHECK-NEXT:    jmpq *__llvm_autojit_resolve@GOTPCREL(%rip)

!llvm.module.flags = !{!0}
!0 = !{i32 8, !"cf-protection-branch", i32 1}
