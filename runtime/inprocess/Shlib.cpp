#include "common/MaterializeGuard.h"
#include "runtime/AutoJITRuntime.h"
#include "runtime/core/AutoJIT.h"

#include <llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h>

#include <cstdint>
#include <string>

LLVM_ATTRIBUTE_USED void linkComponents() {
#if AUTOJIT_LLVM_21
  LOG() << (void *)&llvm_orc_registerJITLoaderGDBWrapper;
#endif
  LOG() << (void *)&llvm_orc_registerJITLoaderGDBAllocAction;
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

// Our static destructors must never run. Library destructors run after them, and
// they might call lazy code for the first time, which needs LLVM's globals. The
// linker binds this for all of our code and exports.txt hides it from others.
extern "C" int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }

static llvm::ExitOnError ExitOnErr("[autojit-runtime] ");

extern "C" void *__llvm_autojit_materialize(void **Slot, uint64_t Guid,
                                             const void *Module) {
  if (!Slot || !Module) {
    LOG() << "Invalid parameters\n";
    exit(1);
  }

  autojit_materialize_guard_t Guard;
  autojit_materialize_guard_enter(&Guard);

  // Load the lazy module on first use
  static auto &JIT = autojit::AutoJIT::get();
  auto *LazyModule = static_cast<const autojit_lazy_module_t *>(Module);
  autojit_pin_image(LazyModule);
  ExitOnErr(JIT.ensureModule(LazyModule));

  // Look up the function symbol
  std::string Symbol = autojit::guidToFnName(Guid, LazyModule->hash);
  uint64_t Addr =
      JIT.lookup(Symbol.c_str(), reinterpret_cast<uint64_t>(LazyModule));
  DBG() << "Materialized " << Symbol << " at address 0x" << hexstr(Addr)
        << "\n";

  // Patch the pointer that is checked by the function frame in static code
  void *Fn = reinterpret_cast<void *>(Addr);
  __atomic_store_n(Slot, Fn, __ATOMIC_RELEASE);
  autojit_materialize_guard_leave(&Guard);
  return Fn;
}
