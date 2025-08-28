// Test debug options for the AutoJIT runtime

// This only works if LLVM was built in debug-mode
// REQUIRES: llvm-debug

// RUN: %clang -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic -o %t.exe
// RUN: env AUTOJIT_DEBUG=On %t.exe 2>&1 | FileCheck %s
//
// CHECK: Looking up { (__autojit_fn_{{[0-9]*}}, RequiredSymbol) } in [ ("main", MatchAllSymbols) ] (required state: Ready)
// CHECK: Dispatching MaterializationUnits...
// CHECK: Done dispatching MaterializationUnits.
// CHECK: Entering OL_applyQueryPhase1
// CHECK: All symbols matched.
// CHECK: Phase 1 succeeded.
// CHECK: Entering OL_completeLookup
// CHECK: Query successfully lodged
// CHECK: Dispatching MaterializationUnits...
// CHECK: Done dispatching MaterializationUnits.
// CHECK: autojit-runtime: Materialized function __autojit_fn_{{[0-9]*}} at address 0x{{[0-9a-f]*}}
//
// CHECK: Ending ExecutionSession
// CHECK: Destroying JITDylib <Process Symbols>
// CHECK: Destroying JITDylib <Platform>
// CHECK: Destroying JITDylib main
//
int main(int argc, char *argv[]) {
  return argc - 1;
}
