// A template can be defined in one source file and used from others, relying on
// the instantiation there. It must stay in the static object, even if lazy code
// is the only user in its file. Inline functions don't need that.
//
// RUN: %clang -O2 -fpass-plugin=%autojit_plugin -S -emit-llvm %s -o - | FileCheck --check-prefix=IR %s
// RUN: rm -rf %t.dir && mkdir -p %t.dir
// RUN: %clang -O2 -fpass-plugin=%autojit_plugin -c %s -o %t.dir/a.o
// RUN: %clang -O2 -fpass-plugin=%autojit_plugin -DUSER -c %S/Inputs/out-of-line-template-user.cpp -o %t.dir/b.o
// RUN: %clang %t.dir/a.o %t.dir/b.o -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t.dir/exe
// RUN: %t.dir/exe | FileCheck %s
//
// IR: define linkonce_odr {{.*}}@_Z9outOfLineIiEiT_
// IR-NOT: define{{.*}}@_Z9inlineFnv
// CHECK: 6

#include "Inputs/out-of-line-template.h"

template <typename T> int outOfLine(T X) {
  int Sum = 0;
  for (T I = 0; I <= X; I += 1)
    Sum += I;
  return Sum;
}

inline int inlineFn() { return 1; }

int useIt(int X) { return outOfLine(X) + inlineFn() - 1; }
