; REQUIRES: aarch64-registered-target
; RUN: env AUTOJIT_STATIC_THRESHOLD=0 %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S %s -o %t.ll
; RUN: FileCheck --check-prefix=IR %s < %t.ll
; RUN: %llc -O0 %t.ll -o - | FileCheck --check-prefix=ASM %s
; RUN: sed -e 's/i32 1, !"Code Model", i32 1/i32 1, !"Code Model", i32 4/' %s \
; RUN:   | env AUTOJIT_STATIC_THRESHOLD=0 %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S -o - \
; RUN:   | FileCheck --check-prefix=LARGE %s

source_filename = "/workspace/llvm-autojit/test/trampoline-aarch64.cpp"
target triple = "aarch64-unknown-linux-gnu"

; Slots initially point to the resolver thunk
; IR: @__llvm_autojit_ptr_add = internal global ptr @__llvm_autojit_resolve_thunk, align 8

; Trampolines pass their entry in x16 and jump through the slot with x17
; IR: define i32 @add(i32 %0, i32 %1) [[TRAMPOLINE:#[0-9]+]] {
; IR-NEXT: entry:
; IR-NEXT:   call void asm sideeffect "adr x16, 1f\0Aadrp x17, ${0:c}\0Aadd x17, x17, :lo12:${0:c}\0Aldar x17, [x17]\0Abr x17\0A1:\0A.xword {{[0-9]+}}\0A.word ${0:c} - 1b\0A.word ${1:c} - 1b", "s,s"(ptr @__llvm_autojit_ptr_add, ptr @__llvm_autojit_module)
; IR-NEXT:   unreachable

; Functions with SME attributes keep the generic trampoline
; IR: define void @streaming() {{.*}}{
; IR:   call ptr @__llvm_autojit_materialize(

; Variadic functions too: GlobalISel would spill vararg registers in a naked
; function
; IR: define i32 @variadic(i32 %0, ...) {{.*}}{
; IR:   call ptr @__llvm_autojit_materialize(

; The thunk jumps to the resolver in the runtime. It gets BTI from the module
; flag, because it's an indirect branch target.
; IR: define internal void @__llvm_autojit_resolve_thunk() [[TRAMPOLINE]] {
; IR-NEXT: entry:
; IR-NEXT:   call void asm sideeffect "adrp x17, :got:${0:c}\0Aldr x17, [x17, :got_lo12:${0:c}]\0Abr x17", "s"(ptr @__llvm_autojit_resolve)

; IR: attributes [[TRAMPOLINE]] = { naked noinline nounwind "branch-target-enforcement" }

; Exactly one landing pad, no frame and no unwind info
; ASM-LABEL: add:
; ASM-NEXT:  // %bb.0:
; ASM-NEXT:    hint #34
; ASM-NEXT:    //APP
; ASM-NEXT:    adr x16, .Ltmp0
; ASM-NEXT:    adrp x17, __llvm_autojit_ptr_add
; ASM-NEXT:    add x17, x17, :lo12:__llvm_autojit_ptr_add
; ASM-NEXT:    ldar x17, [x17]
; ASM-NEXT:    br x17
; ASM-NEXT:  .Ltmp0:
; ASM-NEXT:    .xword {{[0-9]+}}
; ASM-NEXT:    .word __llvm_autojit_ptr_add-.Ltmp0
; ASM-NEXT:    .word .L__llvm_autojit_module-.Ltmp0
; ASM-NEXT:    //NO_APP
; ASM-NEXT:  .Lfunc_end

; ASM-LABEL: __llvm_autojit_resolve_thunk:
; ASM-NEXT:  // %bb.0:
; ASM-NEXT:    hint #34
; ASM-NEXT:    //APP
; ASM-NEXT:    adrp x17, :got:__llvm_autojit_resolve

; With the large code model, the slot might be out of range for adrp
; LARGE-NOT: __llvm_autojit_resolve_thunk
; LARGE: call ptr @__llvm_autojit_materialize(

define i32 @add(i32 %0, i32 %1) uwtable "branch-target-enforcement" {
  %3 = add i32 %0, %1
  ret i32 %3
}

define void @streaming() "aarch64_pstate_sm_enabled" "branch-target-enforcement" "target-features"="+sme" {
  ret void
}

define i32 @variadic(i32 %0, ...) "branch-target-enforcement" {
  ret i32 %0
}

!llvm.module.flags = !{!0, !1}
!0 = !{i32 8, !"branch-target-enforcement", i32 1}
!1 = !{i32 1, !"Code Model", i32 1}
