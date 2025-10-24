#pragma once

#include "AutoJITConfig.h"

#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/Support/DynamicLibrary.h>
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

class AutoJIT {
public:
  AutoJIT();
  ~AutoJIT();

  static AutoJIT &get(std::vector<std::string> &NewModules);
  llvm::Error initialize(llvm::orc::LLJITBuilder &B, bool HaveOrcRuntimeDeps);
  uint64_t lookup(const char *Symbol);
  bool haveHostSymbol(llvm::StringRef Name) const;
  llvm::orc::ThreadSafeModule loadModule(llvm::StringRef FilePath) const;
  llvm::Error submit(llvm::orc::ThreadSafeModule Module);

private:
  std::unique_ptr<llvm::orc::LLJIT> JIT_;
  mutable llvm::sys::DynamicLibrary HostProcess_;
  mutable std::unordered_set<std::string> HostSymbolsCache_;
};

std::string guidToFnName(llvm::GlobalValue::GUID Guid);

} // namespace autojit
