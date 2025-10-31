; Check that link-once functions are materialized only once and have a single static frame
;
; RUN: clang -O0 -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-debug -c %s -o %t.o
; RUN: clang -O0 -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-debug -c %S/Inputs/link_once1.ll -o %t_link_once1.o
; RUN: clang -O0 -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-debug -c %S/Inputs/link_once2.ll -o %t_link_once2.o
; RUN: clang %t.o %t_link_once1.o %t_link_once2.o -rdynamic -L%autojit_runtime_dir -Wl,--whole-archive -lautojit_static-%arch -Wl,--no-whole-archive %fsanitize -o %t_remote.exe
; RUN: %t_remote.exe | FileCheck %s
;
; CHECK: link_once impl = 0x[[IMPL:[0-9a-f]+]]
; CHECK: link_once impl = 0x[[IMPL]]
; CHECK: link_once impl = 0x[[IMPL]]
;
; CHECK: link_once frame = 0x[[FRAME:[0-9a-f]+]]
; CHECK: link_once frame = 0x[[FRAME]]
; CHECK: link_once frame = 0x[[FRAME]]

; ModuleID = '/workspace/llvm-autojit/test/link_once.ll'
source_filename = "/workspace/llvm-autojit/test/link_once.ll"

%"class.llvm::StringRef" = type { ptr, i64 }

@.fmt = private unnamed_addr constant [22 x i8] c"link_once frame = %p\0A\00"

declare noundef i64 @_ZNK4llvm9StringRef4sizeEv(ptr noundef nonnull align 8 dereferenceable(16))
declare ptr @call_link_once1(ptr %s)
declare ptr @call_link_once2(ptr %s)
declare i32 @printf(ptr, ...)

define i32 @main() {
entry:
  %s = alloca %"class.llvm::StringRef", align 8

  %0 = call i64 @_ZNK4llvm9StringRef4sizeEv(ptr %s)
  %ptr1 = call ptr @call_link_once1(ptr %s)
  %ptr2 = call ptr @call_link_once2(ptr %s)

  %fmtptr = getelementptr [19 x i8], ptr @.fmt, i64 0, i64 0
  call i32 (ptr, ...) @printf(ptr %fmtptr, ptr @_ZNK4llvm9StringRef4sizeEv)
  call i32 (ptr, ...) @printf(ptr %fmtptr, ptr %ptr1)
  call i32 (ptr, ...) @printf(ptr %fmtptr, ptr %ptr2)

  ret i32 0
}
