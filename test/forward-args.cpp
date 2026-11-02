// Check that trampolines forward arguments exactly. Here the result is
// returned via sret, so the structs are passed byval on the stack. Variadic
// arguments must be forwarded as well.
//
// RUN: %clang -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang -fpass-plugin=%autojit_plugin %s -rdynamic -L%autojit_runtime_dir -lautojit_static-%arch %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: N = 303002
// CHECK: sum = 10

#include <cstdarg>
#include <cstddef>
#include <cstdio>

struct Range {
  const char *Begin, *End;
};
template <typename T> struct Ref {
  const T *Data;
  size_t Len;
};
struct Result {
  char Buffer[128];
  size_t N;
};

struct Manager {
  int Id;
  Result get(const char *Loc, int Kind, const char *Msg, Ref<Range> Ranges,
             Ref<int> FixIts) const;
};

Result Manager::get(const char *Loc, int Kind, const char *Msg,
                    Ref<Range> Ranges, Ref<int> FixIts) const {
  Result R{};
  for (size_t I = 0; I < Ranges.Len; I += 1)
    R.N += Ranges.Data[I].End - Ranges.Data[I].Begin;
  R.N += FixIts.Len * 1000 + Kind * 100000;
  return R;
}

int sum(int N, ...) {
  va_list Args;
  va_start(Args, N);
  int Sum = 0;
  for (int I = 0; I < N; I += 1)
    Sum += va_arg(Args, int);
  va_end(Args);
  return Sum;
}

int main() {
  const char *Str = "ab";
  Range Ranges[] = {{Str, Str + 2}};
  int FixIts[] = {1, 2, 3};
  Manager M{1};
  Result R = M.get("loc", 3, "msg", {Ranges, 1}, {FixIts, 3});
  printf("N = %zu\n", R.N);
  printf("sum = %d\n", sum(4, 1, 2, 3, 4));
  return 0;
}
