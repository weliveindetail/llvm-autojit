; RUN: %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S %s -o %t.ll
; RUN: FileCheck --check-prefix=IR %s < %t.ll
; RUN: %llc -relocation-model=pic %t.ll -o - | FileCheck --check-prefix=ASM %s

; The import table lists all symbols that lazy code imports from static code.
; Symbols that might not be local to the linked image get an indirect entry
; via the GOT: @ext, @wk and @counter (bitmap 0b00010101 = 0x15).

; IR: @__llvm_autojit_module = private constant { i32, i32, i64, [6 x i32], [1 x i8], [{{[0-9]+}} x i8] } { i32 2, i32 6, i64 {{-?[0-9]+}}, [6 x i32] {{.*}}, [1 x i8] c"\15", [{{[0-9]+}} x i8] c"/tmp/autojit_{{[0-9a-f]+}}.bc\00" }
; IR: call ptr @__llvm_autojit_materialize(ptr @__llvm_autojit_ptr_caller, i64 {{-?[0-9]+}}, ptr @__llvm_autojit_module)

; ASM:      .L__llvm_autojit_module:
; ASM-NEXT:   .long 2
; ASM-NEXT:   .long 6
; ASM-NEXT:   .quad {{-?[0-9]+}}
; ASM-NEXT:   .long ext@GOTPCREL
; ASM-NEXT:   .long hid-
; ASM-NEXT:   .long wk@GOTPCREL
; ASM-NEXT:   .long callee-
; ASM-NEXT:   .long counter@GOTPCREL
; ASM-NEXT:   .long hidden_var-
; ASM-NEXT:   .byte 21
; ASM-NEXT:   .asciz "/tmp/autojit_{{[0-9a-f]+}}.bc"

source_filename = "/workspace/llvm-autojit/test/imports.c"
target triple = "x86_64-pc-linux-gnu"

@counter = global i32 0
@hidden_var = hidden global i32 0

declare i32 @ext(i32)
declare hidden void @hid()
declare extern_weak void @wk()

define dso_local i32 @callee(i32 %x) {
  ret i32 %x
}

define i32 @caller(i32 %x) {
  %a = call i32 @callee(i32 %x)
  %b = call i32 @ext(i32 %a)
  call void @hid()
  %c = load i32, ptr @counter
  %d = load i32, ptr @hidden_var
  %e = icmp eq ptr @wk, null
  ret i32 %b
}
