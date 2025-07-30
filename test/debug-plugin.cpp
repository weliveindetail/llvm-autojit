// Test debug options for the AutoJIT plugin

// AutoJIT pass writes lazy module as .ll file if it runs with debug mode
// RUN: %clang -c %s -o %t.o -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-debug 2>&1 | FileCheck --check-prefix=CHECK-LOG -DSource=%s %s

// CHECK-LOG: autojit-plugin: Processing module [[Source]]
// CHECK-LOG: autojit-plugin: /tmp/autojit_{{[0-9a-f]+}}.ll (source: [[Source]])

// Check that the file path ends up in the object file
// RUN: strings %t.o | FileCheck --check-prefix=CHECK-OBJ %s
// CHECK-OBJ: /tmp/autojit_{{[0-9a-f]+}}.ll

int main() {
  return 0;
}
