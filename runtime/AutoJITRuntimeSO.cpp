#include "AutoJITCommon.h"
#include "AutoJITRuntime.h"

#include "llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h"

#include <cstdint>
#include <string>

LLVM_ATTRIBUTE_USED void linkComponents() {
  LOG() << (void *)&llvm_orc_registerJITLoaderGDBWrapper
        << (void *)&llvm_orc_registerJITLoaderGDBAllocAction;
}

static std::string hexstr(uint64_t Val) {
  static constexpr unsigned NumDigits = sizeof(Val) / 4;
  static const char HexDigits[] = "0123456789ABCDEF";
  std::string Result(NumDigits, '0');

  for (unsigned i = NumDigits - 1; i >= 0; i -= 1) {
    Result[i] = HexDigits[Val % 16];
    Val /= 16;
  }

  return Result;
}

extern "C" void __llvm_autojit_materialize(void **GuidInPtrOut) {
  if (!GuidInPtrOut || *GuidInPtrOut == nullptr) {
    LOG() << "Invalid parameters\n";
    exit(1);
  }

  // Look up the function symbol
  static thread_local auto &JIT = autojit::AutoJIT::get();
  uint64_t Guid = reinterpret_cast<uintptr_t>(*GuidInPtrOut);
  std::string Symbol = autojit::guidToFnName(Guid);

  uint64_t Addr = JIT.lookup(Symbol.c_str());
  DBG() << "Materialized " << Symbol << " at address 0x" << hexstr(Addr)
        << "\n";

  // Patch the pointer that is checked by the function frame in static code
  *GuidInPtrOut = reinterpret_cast<void *>(Addr);
}

extern "C" void __llvm_autojit_register(const char *FilePath) {
  if (!FilePath || strlen(FilePath) == 0) {
    LOG() << "Ignore empty module path\n";
    return;
  }

  autojit::submitModule(FilePath);
}
