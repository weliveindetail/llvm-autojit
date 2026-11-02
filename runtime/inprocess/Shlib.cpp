#include "runtime/AutoJITRuntime.h"
#include "runtime/core/AutoJIT.h"

#include "llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h"

#include <cstdint>
#include <string>

LLVM_ATTRIBUTE_USED void linkComponents() {
  LOG() << (void *)&llvm_orc_registerJITLoaderGDBWrapper
        << (void *)&llvm_orc_registerJITLoaderGDBAllocAction;
}
static std::vector<autojit::ModuleRegistration> ModulesRegistered_;

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

extern "C" void *__llvm_autojit_materialize(void **Slot, uint64_t Guid) {
  if (!Slot) {
    LOG() << "Invalid parameters\n";
    exit(1);
  }

  // Look up the function symbol
  static thread_local auto &JIT = autojit::AutoJIT::get(ModulesRegistered_);
  assert(ModulesRegistered_.empty() && "Modules on first access");

  std::string Symbol = autojit::guidToFnName(Guid);

  uint64_t Addr = JIT.lookup(Symbol.c_str());
  DBG() << "Materialized " << Symbol << " at address 0x" << hexstr(Addr)
        << "\n";

  // Patch the pointer that is checked by the function frame in static code
  void *Fn = reinterpret_cast<void *>(Addr);
  __atomic_store_n(Slot, Fn, __ATOMIC_RELEASE);
  return Fn;
}

extern "C" void __llvm_autojit_register2(const char *FilePath,
                                         const void *ImportTable) {
  if (!FilePath || strlen(FilePath) == 0) {
    LOG() << "Ignore empty module path\n";
    return;
  }
  auto *Imports = static_cast<const autojit_import_table_t *>(ImportTable);
  if (!Imports || Imports->version != AUTOJIT_IMPORT_TABLE_VERSION) {
    LOG() << "Unsupported import table in module " << FilePath << "\n";
    exit(1);
  }

  static std::mutex Registration;
  std::lock_guard<std::mutex> Lock(Registration);

  autojit::initializeDebugLog();
  DBG() << "Registering module " << FilePath << "\n";
  // Paths and tables live in the static objects, so we don't copy them. We
  // only decode the tables once we load the modules.
  ModulesRegistered_.push_back({FilePath, Imports});
}
