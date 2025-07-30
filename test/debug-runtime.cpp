// Test debug options for the AutoJIT runtime

// This only works if LLVM was built in debug-mode
// REQUIRES: llvm-debug

// RUN: %clang -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -rdynamic -o %t.exe
// RUN: env AUTOJIT_DEBUG=On %t.exe 2>&1 | FileCheck %s
//
// CHECK: Looking up { (main$llvm_autojit_module_{{[0-9a-f]*}}, RequiredSymbol) } in [ ("main", MatchAllSymbols) ] (required state: Ready)
// CHECK: Dispatching MaterializationUnits...
// CHECK: Done dispatching MaterializationUnits.
// CHECK: Entering OL_applyQueryPhase1
// CHECK: All symbols matched.
// CHECK: Phase 1 succeeded.
// CHECK: Entering OL_completeLookup
// CHECK: Query successfully completed
// CHECK: Dispatching MaterializationUnits...
// CHECK: Done dispatching MaterializationUnits.
// CHECK: autojit-runtime: Materialized function main
//
// CHECK: Looking up { (_Z3subii$llvm_autojit_module_{{[0-9a-f]*}}, RequiredSymbol) } in [ ("main", MatchAllSymbols) ] (required state: Ready)
// CHECK: Dispatching MaterializationUnits...
// CHECK: Done dispatching MaterializationUnits.
// CHECK: Entering OL_applyQueryPhase1
// CHECK: All symbols matched.
// CHECK: Phase 1 succeeded.
// CHECK: Entering OL_completeLookup
// CHECK: Query successfully completed
// CHECK: Done dispatching MaterializationUnits
// CHECK: autojit-runtime: Materialized function _Z3subii
//
// CHECK: Ending ExecutionSession
// CHECK: Destroying JITDylib main
//
namespace llvm {
  extern bool DebugFlag;
  extern void setCurrentDebugType(const char *Type);
}

// FIXME: Hits assertion "Resolving symbol with incorrect flags" in LLVM
// llvm/lib/ExecutionEngine/Orc/Core.cpp:2915
struct EnableLLVMDebugType {
  EnableLLVMDebugType(const char *Name) {
    llvm::DebugFlag = true;
    llvm::setCurrentDebugType("orc");
  }
};

static EnableLLVMDebugType EnableDebugTypeOrc("orc");

int sub(int a, int b) { return a - b; }

int main(int argc, char *argv[]) {
  return sub(argc, 1);
}
