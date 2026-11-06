; RUN: %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S %s -o - | FileCheck --check-prefix=MEDIUM %s
; RUN: sed -e 's/i32 3}/i32 4}/' %s | %opt --load-pass-plugin=%autojit_plugin -passes=AutoJIT,verify -S -o - | FileCheck --check-prefix=LARGE %s

; With the medium code model, the linker might place large data more than 2GB
; away from the import table. Entries for it must go through the GOT. With the
; large code model, this applies to all symbols.
;
; Imports in order: callee, small, big, ldata, attr_large, attr_small
; MEDIUM: [1 x i8] c"\1C"
; LARGE:  [1 x i8] c"?"

source_filename = "/workspace/llvm-autojit/test/imports-code-model.c"
target triple = "x86_64-pc-linux-gnu"

@small = dso_local global i32 0
@big = dso_local global [2000 x i8] zeroinitializer
@ldata = dso_local global i32 0, section ".ldata.x"
@attr_large = dso_local global i32 0, code_model "large"
@attr_small = dso_local global [2000 x i8] zeroinitializer, code_model "small"

define dso_local i32 @callee() {
  ret i32 0
}

define i32 @caller() {
  %a = call i32 @callee()
  %b = load i32, ptr @small
  %c = load i8, ptr @big
  %d = load i32, ptr @ldata
  %e = load i32, ptr @attr_large
  %f = load i8, ptr @attr_small
  %g = icmp eq ptr @callee, null
  ret i32 %a
}

!llvm.module.flags = !{!0, !1}
!0 = !{i32 1, !"Code Model", i32 3}
!1 = !{i32 1, !"Large Data Threshold", i64 1000}
