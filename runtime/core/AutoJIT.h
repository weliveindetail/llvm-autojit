#pragma once

#include "AutoJITConfig.h"
#include "common/LazyModule.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>

#include <cstdint>
#include <memory>
#include <mutex>
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
class ImportResolver;
class ObjectCacheWriter;


class AutoJIT {
public:
  AutoJIT();
  ~AutoJIT();

  static AutoJIT &get();
  llvm::Error initialize(llvm::orc::LLJITBuilder &B, bool HaveOrcRuntimeDeps);
  uint64_t lookup(const char *Symbol);

  /// Add the lazy module to the JIT, providing the path to the bitcode file,
  /// the hash of its contents and the addresses from the import table in the
  /// module's static object. Uses the cached object if there is one.
  llvm::Error addModule(llvm::StringRef FilePath, uint64_t Hash,
                        llvm::ArrayRef<uint64_t> ImportAddrs);

  /// Add the lazy module that belongs to the given descriptor from a static
  /// object of the host process, unless we added it before.
  llvm::Error ensureModule(const autojit_lazy_module_t *Module);

private:
  llvm::Expected<llvm::orc::ThreadSafeModule>
  loadModule(llvm::StringRef FilePath, uint64_t Hash, size_t NumImports,
             llvm::StringRef CacheStem) const;

  std::unique_ptr<llvm::orc::LLJIT> JIT_;
  bool UseObjectCache_ = true;
  ImportResolver *Imports_ = nullptr;
  std::unique_ptr<ObjectCacheWriter> CacheWriter_;
  // Threads that need the same module wait for it, all others proceed
  struct ModuleState {
    std::once_flag Loaded;
    std::string Error;
  };
  std::mutex ModulesMutex_;
  llvm::DenseMap<const autojit_lazy_module_t *, std::unique_ptr<ModuleState>>
      Modules_;
};

/// Name of the JITed definition of the function with the given GUID in the
/// lazy module with the given hash.
std::string guidToFnName(llvm::GlobalValue::GUID Guid, uint64_t ModuleHash);

} // namespace autojit
