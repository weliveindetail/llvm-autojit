// Materialization blocks all signals. The daemon that the first lazy call spawns
// must not inherit that, or it can't be stopped from the outside.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.exe
// RUN: %t.exe | FileCheck %s
//
// CHECK: SigBlk: 0000000000000000

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void printBlockedSignals(void) {
  char Cmd[128];
  snprintf(Cmd, sizeof(Cmd), "grep SigBlk /proc/$(pgrep -P %d autojitd)/status",
           (int)getpid());
  fflush(stdout);
  if (system(Cmd) != 0)
    abort();
}

int main(void) {
  printBlockedSignals();
  return 0;
}
