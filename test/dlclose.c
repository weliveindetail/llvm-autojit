// JITed code refers to its image, so images with lazy code never unload.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang_c -fPIC -fpass-plugin=%autojit_plugin -shared %S/Inputs/dlclose-plugin.c -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/libplugin.so
// RUN: %clang_c -fPIC -shared -xc /dev/null -o %t.dir/libfiller.so
// RUN: %clang_c %s -DPLUGIN='"%t.dir/libplugin.so"' -DFILLER='"%t.dir/libfiller.so"' -ldl -o %t.dir/main
// RUN: %t.dir/main | FileCheck %s
// CHECK: first: 1
// CHECK: second: 2

#include <dlfcn.h>
#include <stdio.h>

static int call(void) {
  void *H = dlopen(PLUGIN, RTLD_NOW);
  int (*Fn)(void) = (int (*)(void))dlsym(H, "plugin");
  int Result = Fn();
  dlclose(H);
  return Result;
}

int main(void) {
  printf("first: %d\n", call());
  dlopen(FILLER, RTLD_NOW);
  printf("second: %d\n", call());
  return 0;
}
