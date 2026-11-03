// Check that the static object has the same symbols as the original object,
// except for references to the AutoJIT runtime. We ignore symbols that the
// backend creates for code that moved to the lazy module, like libcalls and
// helpers for exception handling.
//
// RUN: %clang -fvisibility-inlines-hidden -c %s -o %t_plain.o
// RUN: %clang -fvisibility-inlines-hidden -fpass-plugin=%autojit_plugin -c %s -o %t_autojit.o
// RUN: %readelf -s --wide %t_plain.o | awk '$5 != "LOCAL" && $8 != "" { print $5, $6, ($7 == "UND" ? "UND" : "DEF"), $8 }' | grep -v -e _Unwind_Resume -e DW.ref. | sort > %t_plain.txt
// RUN: %readelf -s --wide %t_autojit.o | awk '$5 != "LOCAL" && $8 != "" { print $5, $6, ($7 == "UND" ? "UND" : "DEF"), $8 }' | grep -v -e __llvm_autojit_ -e _Unwind_Resume -e DW.ref. | sort > %t_autojit.txt
// RUN: diff %t_plain.txt %t_autojit.txt

#include <cstdio>

__attribute__((visibility("hidden"))) int hiddenFn(int X) { return X + 1; }
__attribute__((visibility("protected"))) int protectedFn(int X) { return X; }

static int Counter = 0;
static int bump() { return ++Counter; }

int Global = 42;
extern int External;

// Its vtable is a linkonce_odr definition that only lazy code uses
struct Shape {
  virtual ~Shape() {}
  virtual int area() const { return Value; }
  int Value = 2;
};

int useShape() {
  Shape S;
  return S.area();
}

struct Widget {
  int get() const { return Value + bump(); } // inline, hidden by flag
  int Value = 1;
};

int useAll() {
  static int LocalStatic = 3;
  Widget W;
  return hiddenFn(W.get()) + protectedFn(Global) + External + LocalStatic++;
}

int main() { return printf("%d\n", useAll() + useShape()) > 0 ? 0 : 1; }
