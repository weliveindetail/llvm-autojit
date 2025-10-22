; ModuleID = '/workspace/llvm-autojit/test/Inputs/link_once2.ll'
source_filename = "/workspace/llvm-autojit/test/Inputs/link_once2.ll"

$_ZNK4llvm9StringRef4sizeEv = comdat any

declare ptr @llvm.returnaddress(i32)
declare i32 @printf(ptr, ...)

@.fmt = private unnamed_addr constant [21 x i8] c"link_once impl = %p\0A\00"

define internal void @print_ip() {
  %ip = call ptr @llvm.returnaddress(i32 0)
  %fmtptr = getelementptr [19 x i8], ptr @.fmt, i64 0, i64 0
  call i32 (ptr, ...) @printf(ptr %fmtptr, ptr %ip)
  ret void
}

define linkonce_odr hidden noundef i64 @_ZNK4llvm9StringRef4sizeEv(ptr noundef nonnull align 8 dereferenceable(16) %this) comdat align 2 {
entry:
  call void @print_ip()
  ret i64 0
}

define ptr @call_link_once2(ptr %s) {
entry:
  %0 = call i64 @_ZNK4llvm9StringRef4sizeEv(ptr %s)
  ret ptr @_ZNK4llvm9StringRef4sizeEv
}
