// Check that the static object has the same symbols as the original object,
// except for references to the AutoJIT runtime.
//
// RUN: %clang -fvisibility-inlines-hidden -c %s -o %t_plain.o
// RUN: %clang -fvisibility-inlines-hidden -fpass-plugin=%autojit_plugin -c %s -o %t_autojit.o
// RUN: %readelf -s --wide %t_plain.o | awk '$5 != "LOCAL" && $8 != "" { print $5, $6, ($7 == "UND" ? "UND" : "DEF"), $8 }' | sort > %t_plain.txt
// RUN: %readelf -s --wide %t_autojit.o | awk '$5 != "LOCAL" && $8 != "" { print $5, $6, ($7 == "UND" ? "UND" : "DEF"), $8 }' | grep -v __llvm_autojit_ | sort > %t_autojit.txt
// RUN: diff %t_plain.txt %t_autojit.txt

#include <cstdio>

__attribute__((visibility("hidden"))) int hiddenFn(int X) { return X + 1; }
__attribute__((visibility("protected"))) int protectedFn(int X) { return X; }

static int Counter = 0;
static int bump() { return ++Counter; }

int Global = 42;
extern int External;

struct Widget {
  int get() const { return Value + bump(); } // inline, hidden by flag
  int Value = 1;
};

int useAll() {
  static int LocalStatic = 3;
  Widget W;
  return hiddenFn(W.get()) + protectedFn(Global) + External + LocalStatic++;
}

int main() { return printf("%d\n", useAll()) > 0 ? 0 : 1; }
