// Forked children have their own connection to the daemon. Programs can exit
// without running the stub's cleanup. Neither may hang or affect the parent. Each
// callee has its own lazy module, so that its first call has to reach the daemon.
//
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %s -o %t.dir/main.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/fork-first.c -o %t.dir/first.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/fork-second.c -o %t.dir/second.o
// RUN: %clang_c -fpass-plugin=%autojit_plugin -c %S/Inputs/fork-third.c -o %t.dir/third.o
// RUN: %clang_c %t.dir/main.o %t.dir/first.o %t.dir/second.o %t.dir/third.o -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t.exe
// RUN: %t.exe | FileCheck %s
// RUN: env -u AUTOJITD_FORCE_SPAWN %t.exe | FileCheck %s
//
// CHECK: first in parent
// CHECK: second in child
// CHECK: first in exec
// CHECK: third in parent

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

void first(const char *Who);
void second(const char *Who);
void third(const char *Who);

int main(int argc, char **argv) {
  if (argc > 1) {
    first("exec");
    fflush(stdout);
    // No exit handlers
    _exit(0);
  }
  first("parent");
  fflush(stdout);

  pid_t Pid = fork();
  if (Pid == 0) {
    second("child");
    fflush(stdout);
    exit(0);
  }
  int Status;
  waitpid(Pid, &Status, 0);
  if (!WIFEXITED(Status) || WEXITSTATUS(Status))
    return 1;

  // The child's socket doesn't survive exec
  Pid = fork();
  if (Pid == 0) {
    execl(argv[0], argv[0], "exec", NULL);
    _exit(1);
  }
  waitpid(Pid, &Status, 0);
  if (!WIFEXITED(Status) || WEXITSTATUS(Status))
    return 1;

  third("parent");
  return 0;
}
