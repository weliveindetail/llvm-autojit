#pragma once

#include "AutoJITConfig.h"
#include "common/ImportTable.h"

#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>

extern bool g_autojit_debug;

#if defined(NDEBUG)
#define DBG() for (bool _c = false; _c; _c = false)                            \
                ::llvm::nulls()
#else
#define DBG() for (bool _c = g_autojit_debug; _c; _c = false)                  \
                ::llvm::dbgs() << "[autojit-runtime] "
#endif

#define LOG() ::llvm::errs() << "[autojit-runtime] "

namespace autojit {

void initializeDebugLog();

struct ModuleRegistration {
  const char *FilePath;
  const autojit_import_table_t *Imports;
};

class AutoJIT {
public:
  AutoJIT();
  ~AutoJIT();

  static AutoJIT &get(std::vector<ModuleRegistration> &NewModules);
  llvm::Error initialize(llvm::orc::LLJITBuilder &B, bool HaveOrcRuntimeDeps);
  uint64_t lookup(const char *Symbol);

  /// Load the lazy module from FilePath and add it to the JIT. ImportAddrs are
  /// the addresses from the import table in the module's static object.
  llvm::Error addModule(llvm::StringRef FilePath, uint64_t ImportsHash,
                        llvm::ArrayRef<uint64_t> ImportAddrs);

private:
  llvm::Expected<llvm::orc::ThreadSafeModule>
  loadModule(llvm::StringRef FilePath, uint64_t ImportsHash,
             llvm::ArrayRef<uint64_t> ImportAddrs,
             llvm::orc::SymbolMap &Imports) const;

  std::unique_ptr<llvm::orc::LLJIT> JIT_;
  llvm::orc::JITDylib *HostImports_ = nullptr;
};

std::string guidToFnName(llvm::GlobalValue::GUID Guid);

} // namespace autojit
