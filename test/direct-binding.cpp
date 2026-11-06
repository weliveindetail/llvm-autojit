// Lazy code calls functions in its own module directly. Only functions with a
// use outside of calls need a trampoline, so that their address is the same in
// static and lazy code and across modules.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin -S -emit-llvm %s -o - | FileCheck --check-prefix=IR %s
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main.o
// RUN: %clang -O0 -fpass-plugin=%autojit_plugin -c %S/Inputs/direct-binding-other.cpp -o %t.dir/other.o
// RUN: %clang %t.dir/main.o %t.dir/other.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/inprocess
// RUN: %t.dir/inprocess | FileCheck %s
// RUN: %clang %t.dir/main.o %t.dir/other.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.dir/remote
// RUN: %t.dir/remote | FileCheck %s
//
// A strong function in a shared library might get interposed, so calls in its
// own module must keep going through the dynamic linker
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -c %S/Inputs/direct-binding-lib.c -o %t.dir/lib.o
// RUN: %clang_c -shared %t.dir/lib.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/liblazy.so
// RUN: %clang_c -fPIC -shared -xc %S/Inputs/direct-binding-preload.c -o %t.dir/libpreload.so
// RUN: %clang_c -xc %S/Inputs/direct-binding-main.c -L%t.dir -Wl,-rpath,%t.dir -llazy -o %t.dir/interpose
// RUN: %t.dir/interpose | FileCheck --check-prefix=NOPRELOAD %s
// RUN: env LD_PRELOAD=%t.dir/libpreload.so %t.dir/interpose | FileCheck --check-prefix=PRELOAD %s
// NOPRELOAD: outer: 1
// PRELOAD: outer: 42
//
// -fno-semantic-interposition makes these dso_local, but the linker still
// considers them preemptible. So the import table can't refer to them directly.
// RUN: %clang_c -fPIC -fno-semantic-interposition -fpass-plugin=%autojit_plugin -c %S/Inputs/direct-binding-nosem.c -o %t.dir/nosem.o
// RUN: %clang_c -shared %t.dir/nosem.o -o %t.dir/libnosem.so
// RUN: %clang_c -shared -fuse-ld=bfd %t.dir/nosem.o -o %t.dir/libnosem_bfd.so
//
// IR-NOT: @__llvm_autojit_ptr__Z10onlyCalledi
// IR-DAG: @__llvm_autojit_ptr__Z9addrTakeni = {{.*}}comdat($_Z9addrTakeni)
// IR-DAG: @__llvm_autojit_ptr__ZL8callbacki =
// IR-NOT: define{{.*}}@_Z10onlyCalledi
// IR: define linkonce_odr {{.*}}@_Z9addrTakeni(
//
// A function in llvm.used and a variable initializer must get the same result
// in the plugin and the runtime, no matter the order of its uses. They would
// report a mismatch in their import lists otherwise.
// RUN: %clang_c -fpass-plugin=%autojit_plugin -xc %S/Inputs/direct-binding-used.c -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/used
// RUN: %t.dir/used | FileCheck --check-prefix=USED %s
// USED: used: 3
//
// CHECK: called: 11
// CHECK: same inline address: 1
// CHECK: same local address: 1
// CHECK: callback: 13

#include "Inputs/direct-binding.h"

#include <cstdio>

Fn Table = callback;

static int same() { return Table == callback; }

int main() {
  printf("called: %d\n", onlyCalled(10));
  printf("same inline address: %d\n", getAddrTaken() == addrTaken);
  printf("same local address: %d\n", same());
  printf("callback: %d\n", Table(10));
  return 0;
}
