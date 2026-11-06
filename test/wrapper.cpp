// The compiler wrappers add the plugin and the runtime for any linker. They
// disable .deplibs, so lld doesn't add the runtime a second time.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir/pic
// RUN: %autojit_clang -c %S/Inputs/wrapper-lib.c -o %t.dir/lib.o 2>&1 | count 0
// RUN: %autojit_clangxx -c %s -o %t.dir/main.o 2>&1 | count 0
// RUN: %llvm-nm %t.dir/lib.o | FileCheck --check-prefix=LAZY %s
// RUN: %readelf -S %t.dir/lib.o | FileCheck --check-prefix=NO-DEPLIBS %s
// LAZY: U __llvm_autojit_resolve
// NO-DEPLIBS-NOT: .deplibs
//
// Default mode: the static stub, with each linker
// RUN: %autojit_clangxx -fuse-ld=bfd %t.dir/main.o %t.dir/lib.o -o %t.dir/bfd 2>&1 | count 0
// RUN: %llvm-nm %t.dir/bfd | FileCheck --check-prefix=STUB %s
// RUN: %t.dir/bfd | FileCheck %s
// RUN: %if gold %{ %autojit_clangxx -fuse-ld=gold %t.dir/main.o %t.dir/lib.o -o %t.dir/gold %}
// RUN: %if gold %{ %t.dir/gold | FileCheck %s %}
// RUN: %if lld %{ %autojit_clangxx -fuse-ld=lld %t.dir/main.o %t.dir/lib.o -o %t.dir/lld %}
// RUN: %if lld %{ %readelf -d %t.dir/lld | FileCheck --check-prefix=NO-RUNTIME %s %}
// RUN: %if lld %{ %t.dir/lld | FileCheck %s %}
// STUB: T __llvm_autojit_resolve
// NO-RUNTIME-NOT: libautojit-runtime
//
// Compile and link in one step, with the C driver as well
// RUN: %autojit_clang -c %S/Inputs/wrapper-lib.c -o %t.dir/lib2.o
// RUN: %autojit_clangxx %s %t.dir/lib2.o -o %t.dir/onestep
// RUN: %t.dir/onestep | FileCheck %s
//
// In-process runtime
// RUN: env AUTOJIT_MODE=inprocess %autojit_clangxx %t.dir/main.o %t.dir/lib.o -o %t.dir/inprocess
// RUN: %readelf -d %t.dir/inprocess | FileCheck --check-prefix=INPROCESS %s
// RUN: %t.dir/inprocess | FileCheck %s
// INPROCESS: NEEDED{{.*}}libautojit-runtime.so
// RUN: %if lld %{ env AUTOJIT_MODE=inprocess %autojit_clangxx -fuse-ld=lld %t.dir/main.o %t.dir/lib.o -o %t.dir/inprocess_lld %}
// RUN: %if lld %{ %readelf -d %t.dir/inprocess_lld | FileCheck --check-prefix=INPROCESS --check-prefix=ONCE %s %}
// ONCE-NOT: NEEDED{{.*}}libautojit-runtime.so
//
// Stub with debugger support
// RUN: env AUTOJIT_MODE=stub-debug %autojit_clangxx %t.dir/main.o %t.dir/lib.o -o %t.dir/debug
// RUN: %llvm-nm %t.dir/debug | FileCheck --check-prefix=DEBUG %s
// RUN: %t.dir/debug | FileCheck %s
// DEBUG: __jit_debug_descriptor
//
// Fully static
// RUN: %autojit_clangxx -static %t.dir/main.o %t.dir/lib.o -o %t.dir/static
// RUN: %t.dir/static | FileCheck %s
//
// Shared library
// RUN: env AUTOJIT_DIR=%t.dir/pic %autojit_clang -fPIC -c %S/Inputs/wrapper-lib.c -o %t.dir/lib_pic.o
// RUN: %autojit_clang -shared -Wl,-z,defs %t.dir/lib_pic.o -o %t.dir/libwrapper.so
// RUN: %autojit_clangxx %t.dir/main.o -L%t.dir -Wl,-rpath,%t.dir -lwrapper -o %t.dir/withlib
// RUN: %t.dir/withlib | FileCheck %s
//
// Relocatable objects don't get the stub, only the final link
// RUN: %autojit_clangxx -r %t.dir/main.o %t.dir/lib.o -o %t.dir/partial.o
// RUN: %llvm-nm %t.dir/partial.o | FileCheck --check-prefix=LAZY %s
// RUN: %autojit_clangxx %t.dir/partial.o -o %t.dir/from_partial
// RUN: %t.dir/from_partial | FileCheck %s
//
// Neither does -nostdlib
// RUN: %autojit_clang -shared -nostdlib %t.dir/lib_pic.o -o %t.dir/libnostd.so
// RUN: %llvm-nm %t.dir/libnostd.so | FileCheck --check-prefix=LAZY %s
//
// Invocations that don't link stay quiet and work
// RUN: %autojit_clang --version | FileCheck --check-prefix=VERSION %s
// RUN: %autojit_clang -v 2>&1 | FileCheck --check-prefix=VERSION %s
// RUN: %autojit_clang -E -xc /dev/null 2>&1 | not grep warning
// RUN: %autojit_clang -fsyntax-only -xc /dev/null 2>&1 | count 0
// RUN: %autojit_clang -dumpmachine | count 1
// RUN: %autojit_clang -print-resource-dir | count 1
// VERSION: clang version
//
// Arguments keep their quoting
// RUN: mkdir -p "%t.dir/with space"
// RUN: cp %S/Inputs/wrapper-lib.c "%t.dir/with space/lib.c"
// RUN: %autojit_clangxx -DSUFFIX='"a b"' %s -xc "%t.dir/with space/lib.c" -o %t.dir/quoted
// RUN: %t.dir/quoted | FileCheck --check-prefix=QUOTED %s
// QUOTED: 42 a b
//
// Unknown modes fail
// RUN: env AUTOJIT_MODE=nope not %autojit_clang --version 2>&1 | FileCheck --check-prefix=MODE %s
// MODE: unknown AUTOJIT_MODE 'nope'
//
// CHECK: 42

#include <cstdio>

extern "C" int helper(int X);

#ifndef SUFFIX
#define SUFFIX ""
#endif

int main() {
  std::printf("%d %s\n", helper(1), SUFFIX);
  return 0;
}
