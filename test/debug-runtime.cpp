// Test debug options for the AutoJIT runtime

// This only works if LLVM was built in debug-mode
// REQUIRES: llvm-debug

// RUN: %clang %s -fpass-plugin=%autojit_plugin -rdynamic -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %clang %s -fpass-plugin=%autojit_plugin -rdynamic -L%autojit_runtime_dir -Wl,--whole-archive -lautojit_static-%arch -Wl,--no-whole-archive %fsanitize -o %t_remote.exe
// RUN: env AUTOJIT_DEBUG=On %t_inprocess.exe 2>&1 | FileCheck %s
// RUN: env AUTOJIT_DEBUG=On env AUTOJITD_FULL_SHUTDOWN=On %t_remote.exe 2>&1 | FileCheck %s
//
// CHECK:     Looking up { (__autojit_fn_{{[0-9]*}}, RequiredSymbol) } in [ ("main", MatchAllSymbols) ] (required state: Ready)
// CHECK:     Dispatching MaterializationUnits...
// CHECK:     Done dispatching MaterializationUnits.
// CHECK:     Entering OL_applyQueryPhase1
// CHECK:     All symbols matched.
// CHECK:     Phase 1 succeeded.
// CHECK:     Entering OL_completeLookup
// CHECK:     Query successfully lodged
// CHECK:     Dispatching MaterializationUnits...
//
// Order differs between in-process and remote JIT:
// CHECK-DAG: Adding debug object to GDB JIT interface
// CHECK-DAG: Done dispatching MaterializationUnits.
//
// CHECK:     Materialized __autojit_fn_{{[0-9]*}} at address 0x{{[0-9a-f]*}}
//
// In remote JIT, we get this output only with full synchronous shutdown:
// CHECK:     Ending ExecutionSession
// CHECK-DAG: Destroying JITDylib <Process Symbols>
// CHECK-DAG: Destroying JITDylib <Platform>
// CHECK-DAG: Destroying JITDylib main
//
int main(int argc, char *argv[]) {
  return argc - 1;
}
