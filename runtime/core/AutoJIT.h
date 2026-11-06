#pragma once

#include "AutoJITConfig.h"
#include "common/LazyModule.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/ExecutionEngine/Orc/LLJIT.h>
#include <llvm/ExecutionEngine/Orc/Shared/WrapperFunctionUtils.h>
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
#if AUTOJIT_LLVM_21
using WFBuffer = llvm::orc::shared::WrapperFunctionResult;
using CWFBuffer = llvm::orc::shared::CWrapperFunctionResult;
#else
using WFBuffer = llvm::orc::shared::WrapperFunctionBuffer;
using CWFBuffer = llvm::orc::shared::CWrapperFunctionBuffer;
#endif
} // namespace autojit

namespace autojit {

void initializeDebugLog();
class ImportResolver;
class ObjectCacheWriter;


class AutoJIT {
public:
  AutoJIT();
  ~AutoJIT();

  static AutoJIT &get();
  llvm::Error initialize(llvm::orc::LLJITBuilder &B);

  /// Find a function in the lazy module that was added with the given key.
  uint64_t lookup(const char *Symbol, uint64_t ModuleKey);

  /// Add the lazy module to the JIT, providing the path to the bitcode file,
  /// the hash of its contents and the addresses from the import table in the
  /// module's static object. Uses the cached object if there is one. The key
  /// identifies the static object in the process, because one lazy module can
  /// be part of several images with different addresses.
  llvm::Error addModule(llvm::StringRef FilePath, uint64_t Hash,
                        llvm::ArrayRef<uint64_t> ImportAddrs,
                        uint64_t ModuleKey);

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
  std::mutex DylibsMutex_;
  llvm::DenseSet<uint64_t> KnownHashes_;
  llvm::DenseMap<uint64_t, llvm::orc::JITDylib *> Dylibs_;
  std::mutex ModulesMutex_;
  llvm::DenseMap<const autojit_lazy_module_t *, std::unique_ptr<ModuleState>>
      Modules_;
};

/// Name of the JITed definition of the function with the given GUID in the
/// lazy module with the given hash.
std::string guidToFnName(llvm::GlobalValue::GUID Guid, uint64_t ModuleHash);

} // namespace autojit
