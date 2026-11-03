; RUN: %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S %s -o - | FileCheck %s

source_filename = "/workspace/llvm-autojit/test/trampoline.cpp"
target triple = "x86_64-pc-linux-gnu"

; Descriptor of the lazy module with its path
; CHECK: @__llvm_autojit_module = private constant { i32, i32, i64, [0 x i32], [0 x i8], [49 x i8] } { i32 2, i32 0, i64 {{-?[0-9]+}}, {{.*}}, [49 x i8] c"/tmp/autojit_e897fd8886de1380cf0e7d06010251b0.bc\00" }

; Slots initially point to the resolver thunk. Slots of linkonce functions go
; into their comdat.
; CHECK: @__llvm_autojit_ptr__Z3addii = internal global ptr @__llvm_autojit_resolve_thunk, align 8
; CHECK: @__llvm_autojit_ptr__Z6inlinei = internal global ptr @__llvm_autojit_resolve_thunk, comdat($_Z6inlinei), align 8

; Functions are reduced to trampolines that pass their entry in r11 and jump
; through the slot. The entry holds the GUID and offsets to slot and module.
; CHECK: define noundef i32 @_Z3addii(i32 noundef %0, i32 noundef %1) [[TRAMPOLINE:#[0-9]+]] {
; CHECK-NEXT: entry:
; CHECK-NEXT:   call void asm sideeffect "leaq 1f(%rip), %r11\0Ajmpq *${0:P}(%rip)\0A1:\0A.quad 11725454554070107058\0A.long ${0:P} - 1b\0A.long ${1:P} - 1b", "s,s"(ptr @__llvm_autojit_ptr__Z3addii, ptr @__llvm_autojit_module)
; CHECK-NEXT:   unreachable
define noundef i32 @_Z3addii(i32 noundef %0, i32 noundef %1) noinline optnone uwtable {
  %3 = add nsw i32 %0, %1
  ret i32 %3
}

; Trampolines must never be inlined
; CHECK: define linkonce_odr i32 @_Z6inlinei(i32 %0) [[NAKED:#[0-9]+]] comdat {
$_Z6inlinei = comdat any
define linkonce_odr i32 @_Z6inlinei(i32 %0) alwaysinline comdat {
  ret i32 %0
}

; The thunk jumps to the resolver in the runtime
; CHECK: define internal void @__llvm_autojit_resolve_thunk() [[NAKED]] {
; CHECK-NEXT: entry:
; CHECK-NEXT:   call void asm sideeffect "jmpq *__llvm_autojit_resolve@GOTPCREL(%rip)", ""()

; No frames and no unwind info
; CHECK: attributes [[TRAMPOLINE]] = { naked noinline nounwind optnone }
; CHECK: attributes [[NAKED]] = { naked noinline nounwind }

; CHECK-NOT: __llvm_autojit_materialize
