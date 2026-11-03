// Check that lazy modules and cached objects go to the configured directory
//
// RUN: rm -rf %t.dir %t.rel && mkdir -p %t.rel
// RUN: env AUTOJIT_DIR=%t.dir %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.o
// RUN: ls %t.dir | FileCheck --check-prefix=LAZY %s
// LAZY: autojit_{{[0-9a-f]+}}.bc
//
// The runtime caches the compiled object next to the lazy module
// RUN: %clang_c %t.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.exe
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t.exe | FileCheck --check-prefix=OUT %s
// RUN: ls %t.dir | FileCheck --check-prefix=CACHE %s
// CACHE: autojit_{{[0-9a-f]+}}_{{[0-9a-f]+}}_r{{[0-9]+}}.o
// RUN: env -u AUTOJIT_DISABLE_OBJECT_CACHE %t.exe | FileCheck --check-prefix=OUT %s
// RUN: ls %t.dir | FileCheck --check-prefix=CACHE %s
// RUN: %t.exe | FileCheck --check-prefix=OUT %s
//
// Relative directories are resolved against the working directory of the
// compiler, so the runtime finds them from anywhere
// RUN: cd %t.rel && env AUTOJIT_DIR=autojit %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t_rel.o
// RUN: ls %t.rel/autojit | FileCheck --check-prefix=LAZY %s
// RUN: %clang_c %t_rel.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_rel.exe
// RUN: %t_rel.exe | FileCheck --check-prefix=OUT %s
//
// The option works if the plugin is loaded before options are parsed
// RUN: rm -rf %t.opt
// RUN: %clang_c -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-dir=%t.opt -c %s -o %t_opt.o
// RUN: ls %t.opt | FileCheck --check-prefix=LAZY %s
//
// RUN: %clang_c %t.o -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck --check-prefix=OUT %s
//
// OUT: Hello from the output directory

#include <stdio.h>

int main() {
  puts("Hello from the output directory");
  return 0;
}
