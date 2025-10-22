// Test debug options for the AutoJIT plugin

// AutoJIT pass writes lazy module as .ll file if it runs with debug mode
// RUN: %clang -c %s -o %t.o -fpass-plugin=%autojit_plugin -Xclang -load -Xclang %autojit_plugin -mllvm -autojit-debug 2>&1 | FileCheck --check-prefix=CHECK-LOG -DPath=%p %s
// RUN: env AUTOJIT_DEBUG=On %clang -c %s -o %t.o -fpass-plugin=%autojit_plugin 2>&1 | FileCheck --check-prefix=CHECK-LOG -DPath=%p %s
//
// CHECK-LOG: autojit-plugin: /tmp/autojit_[[HASH:[0-9a-f]+]]_incoming.ll (source: [[Path]]/debug-plugin.cpp)
// CHECK-LOG: autojit-plugin: Processing module [[Path]]/debug-plugin.cpp
// CHECK-LOG: autojit-plugin: /tmp/autojit_[[HASH]].ll
// CHECK-LOG: autojit-plugin: /tmp/autojit_[[HASH]]_static.ll

// Check that the file path ends up in the object file
// RUN: strings %t.o | FileCheck --check-prefix=CHECK-OBJ %s
//
// CHECK-OBJ: /tmp/autojit_{{[0-9a-f]+}}.ll

int main() {
  return 0;
}
