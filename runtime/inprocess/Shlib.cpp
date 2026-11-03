#include "runtime/AutoJITRuntime.h"
#include "runtime/core/AutoJIT.h"

#include <llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h>

#include <cstdint>
#include <string>

LLVM_ATTRIBUTE_USED void linkComponents() {
  LOG() << (void *)&llvm_orc_registerJITLoaderGDBWrapper
        << (void *)&llvm_orc_registerJITLoaderGDBAllocAction;
}

static std::string hexstr(uint64_t Val) {
  static constexpr int NumDigits = sizeof(Val) * 2;
  static const char HexDigits[] = "0123456789abcdef";
  std::string Result(NumDigits, '0');

  for (int i = NumDigits - 1; i >= 0; i -= 1) {
    Result[i] = HexDigits[Val % 16];
    Val /= 16;
  }

  return Result;
}

static llvm::ExitOnError ExitOnErr("[autojit-runtime] ");

extern "C" void *__llvm_autojit_materialize(void **Slot, uint64_t Guid,
                                             const void *Module) {
  if (!Slot || !Module) {
    LOG() << "Invalid parameters\n";
    exit(1);
  }

  // Load the lazy module on first use
  static auto &JIT = autojit::AutoJIT::get();
  auto *LazyModule = static_cast<const autojit_lazy_module_t *>(Module);
  ExitOnErr(JIT.ensureModule(LazyModule));

  // Look up the function symbol
  std::string Symbol = autojit::guidToFnName(Guid, LazyModule->hash);
  uint64_t Addr = JIT.lookup(Symbol.c_str());
  DBG() << "Materialized " << Symbol << " at address 0x" << hexstr(Addr)
        << "\n";

  // Patch the pointer that is checked by the function frame in static code
  void *Fn = reinterpret_cast<void *>(Addr);
  __atomic_store_n(Slot, Fn, __ATOMIC_RELEASE);
  return Fn;
}
