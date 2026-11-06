// Coroutines need CoroSplit, even at -O0. It runs after the plugin, so the
// runtime must run it.
//
// RUN: %clang -std=c++20 -O0 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang -std=c++20 -O2 -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
// CHECK: coroutine: 3

#include <coroutine>
#include <cstdio>

struct Gen {
  struct promise_type {
    int Val;
    Gen get_return_object() {
      return Gen{std::coroutine_handle<promise_type>::from_promise(*this)};
    }
    std::suspend_always initial_suspend() { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    std::suspend_always yield_value(int V) {
      Val = V;
      return {};
    }
    void return_void() {}
    void unhandled_exception() {}
  };
  std::coroutine_handle<promise_type> H;
};

Gen count() {
  for (int I = 0; I < 3; I += 1)
    co_yield I;
}

int main() {
  Gen G = count();
  int Sum = 0;
  while (!G.H.done()) {
    G.H.resume();
    if (!G.H.done())
      Sum += G.H.promise().Val;
  }
  G.H.destroy();
  printf("coroutine: %d\n", Sum);
  return 0;
}
