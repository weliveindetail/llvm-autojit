// lld puts the static stub on the link line through .deplibs. Other linkers
// ignore it, so they need the runtime explicitly.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir/lto
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -c %S/Inputs/deplibs-lib.c -o %t.dir/lib.o
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main.o
//
// Several objects name it, but we get one stub and no shared runtime
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/main.o %t.dir/lib.o -o %t.dir/exe_lld %}
// RUN: %if lld %{ %llvm-nm %t.dir/exe_lld | FileCheck --check-prefix=STUB %s %}
// RUN: %if lld %{ %readelf -d %t.dir/exe_lld | FileCheck --check-prefix=NO-RUNTIME %s %}
// RUN: %if lld %{ %t.dir/exe_lld 1 2 | FileCheck %s %}
// STUB: T __llvm_autojit_resolve
// NO-RUNTIME-NOT: libautojit-runtime
//
// With LTO as well
// RUN: %if lld %{ env AUTOJIT_DIR=%t.dir/lto %clang_c -flto -fPIC -fpass-plugin=%autojit_plugin -c %S/Inputs/deplibs-lib.c -o %t.dir/lib_lto.o %}
// RUN: %if lld %{ %clang_c -flto -fuse-ld=lld %t.dir/main.o %t.dir/lib_lto.o -o %t.dir/exe_lto %}
// RUN: %if lld %{ %llvm-nm %t.dir/exe_lto | FileCheck --check-prefix=STUB %s %}
// RUN: %if lld %{ %t.dir/exe_lto 1 2 | FileCheck %s %}
//
// Fully static
// RUN: %if lld %{ %clang_c -fuse-ld=lld -static %t.dir/main.o %t.dir/lib.o -o %t.dir/exe_lld_static %}
// RUN: %if lld %{ %t.dir/exe_lld_static 1 2 | FileCheck %s %}
//
// A shared library with strict linker flags gets a stub as well
// RUN: %if lld %{ %clang_c -fuse-ld=lld -shared -Wl,-z,defs,--no-undefined %t.dir/lib.o -o %t.dir/liblazy.so %}
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/main.o -L%t.dir -Wl,-rpath,%t.dir -llazy -o %t.dir/exe_lld_so %}
// RUN: %if lld %{ %t.dir/exe_lld_so 1 2 | FileCheck %s %}
//
// Relocatable objects pass it on to the final link
// RUN: %if lld %{ %clang_c -fuse-ld=lld -r %t.dir/main.o %t.dir/lib.o -o %t.dir/partial.o %}
// RUN: %if lld %{ %llvm-nm %t.dir/partial.o | FileCheck --check-prefix=UNDEF-RESOLVE %s %}
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/partial.o -o %t.dir/exe_partial %}
// RUN: %if lld %{ %t.dir/exe_partial 1 2 | FileCheck %s %}
// UNDEF-RESOLVE: U __llvm_autojit_resolve
//
// Explicit runtimes win and don't get on the link line twice
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/exe_lld_rt %}
// RUN: %if lld %{ %readelf -d %t.dir/exe_lld_rt | FileCheck --check-prefix=RUNTIME-ONCE %s %}
// RUN: %if lld %{ %t.dir/exe_lld_rt 1 2 | FileCheck %s %}
// RUNTIME-ONCE: NEEDED{{.*}}libautojit-runtime.so
// RUNTIME-ONCE-NOT: NEEDED{{.*}}libautojit-runtime.so
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/main.o %t.dir/lib.o -L%autojit_runtime_dir -lautojit_static_ldscript -o %t.dir/exe_lld_explicit %}
// RUN: %if lld %{ %t.dir/exe_lld_explicit 1 2 | FileCheck %s %}
//
// AUTOJIT_RUNTIME selects another library at compile time, here with an absolute
// path, so programs start without an rpath
// RUN: %if lld %{ env AUTOJIT_RUNTIME=%autojit_runtime_dir/libautojit-runtime.so %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main_rt.o %}
// RUN: %if lld %{ env AUTOJIT_RUNTIME=%autojit_runtime_dir/libautojit-runtime.so %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/deplibs-lib.c -o %t.dir/lib_rt.o %}
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/main_rt.o %t.dir/lib_rt.o -o %t.dir/exe_lld_rt2 %}
// RUN: %if lld %{ %readelf -d %t.dir/exe_lld_rt2 | FileCheck --check-prefix=RUNTIME-ONCE %s %}
// RUN: %if lld %{ %t.dir/exe_lld_rt2 1 2 | FileCheck %s %}
// RUN: %if lld %{ env AUTOJIT_RUNTIME=%autojit_runtime_dir/libautojit-stub.so %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main_stub.o %}
// RUN: %if lld %{ env AUTOJIT_RUNTIME=%autojit_runtime_dir/libautojit-stub.so %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/deplibs-lib.c -o %t.dir/lib_stub.o %}
// RUN: %if lld %{ %clang_c -fuse-ld=lld %t.dir/main_stub.o %t.dir/lib_stub.o -o %t.dir/exe_lld_stub %}
// RUN: %if lld %{ %readelf -d %t.dir/exe_lld_stub | FileCheck --check-prefix=DEPLIBS-STUB %s %}
// RUN: %if lld %{ %t.dir/exe_lld_stub 1 2 | FileCheck %s %}
// DEPLIBS-STUB: NEEDED{{.*}}/libautojit-stub.so
//
// The object names the archive
// RUN: %readelf -p .deplibs %t.dir/main.o | FileCheck --check-prefix=SECTION %s
// SECTION: /libautojit_static.a
//
// The parameter and its environment variable disable it, both for lld and in
// the object
// RUN: env AUTOJIT_NO_DEPLIBS=On %clang_c -fPIC -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main_no_env.o
// RUN: %readelf -S %t.dir/main_no_env.o | FileCheck --check-prefix=NO-SECTION %s
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-no-deplibs -c %s -o %t.dir/main_no_opt.o
// RUN: %readelf -S %t.dir/main_no_opt.o | FileCheck --check-prefix=NO-SECTION %s
// RUN: env AUTOJIT_NO_DEPLIBS=Off %clang_c -fPIC -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main_off.o
// RUN: %readelf -S %t.dir/main_off.o | FileCheck --check-prefix=HAS-SECTION %s
// NO-SECTION-NOT: .deplibs
// HAS-SECTION: .deplibs
//
// Without the parameter, GNU ld reports a missing runtime at link time
// RUN: not %clang_c -fuse-ld=bfd %t.dir/main.o %t.dir/lib.o -o %t.dir/exe_ld 2>&1 | FileCheck --check-prefix=UNDEF %s
// UNDEF: undefined reference to `__llvm_autojit_
//
// The plugin twice on the command line must not lazify the trampolines
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -fpass-plugin=%autojit_plugin -c %S/Inputs/deplibs-lib.c -o %t.dir/lib_twice.o
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main_twice.o
// RUN: %clang_c %t.dir/main_twice.o %t.dir/lib_twice.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/exe_twice
// RUN: %t.dir/exe_twice 1 2 | FileCheck %s
//
// CHECK: ctor: 1 2.5 x 7.25
// CHECK: varargs: 42
// CHECK: main: 3 args

#include <stdio.h>

double first(int I, double D, const char *S, float F);
int vsum(int N, ...);

__attribute__((constructor)) static void init(void) { first(1, 2.5, "x", 7.25f); }

int main(int Argc, char **Argv) {
  printf("varargs: %d\n", vsum(3, 20, 20, 2));
  printf("main: %d args\n", Argc);
  return Argv[0] == NULL;
}
