#pragma once

#include "llvm/ADT/StableHashing.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/xxhash.h"

namespace autojit {

inline bool isStaticInit(const llvm::Function &F) {
  llvm::StringRef FuncName = F.getName();
  if (FuncName.starts_with("_GLOBAL__sub_"))
    return true;
  if (FuncName.starts_with("__cxx_global_var_init"))
    return true;
  return false;
}

inline bool hasLiveUses(llvm::GlobalValue &GV) {
  // Dead constant users exist in memory, but not in the bitcode. Drop them so
  // that the plugin and the runtime see the same uses.
  if (GV.use_empty())
    return false;
  GV.removeDeadConstantUsers();
  return !GV.use_empty();
}

/// Visit all symbols that the lazy module imports from the host process. The
/// plugin calls this right before it saves the lazy module, and the runtime
/// calls it right after it loads the module. Both must see the same sequence,
/// because the import table in the static object matches entries by index.
///
/// Keep this in sync with AutoJIT::loadModule(): it turns each of them into a
/// declaration (or adds a declaration for it in case of function definitions).
template <typename CallbackT>
void forEachImport(llvm::Module &M, CallbackT Callback) {
  using namespace llvm;
  for (Function &F : M) {
    if (F.isIntrinsic() || !hasLiveUses(F))
      continue;
    if (!F.isDeclaration()) {
      if (F.hasLocalLinkage() || isStaticInit(F))
        continue;
      if (F.hasAvailableExternallyLinkage() &&
          F.hasFnAttribute(Attribute::AlwaysInline))
        continue;
    }
    Callback(static_cast<GlobalValue &>(F));
  }
  for (GlobalVariable &GV : M.globals()) {
    if (GV.getName().starts_with("llvm.") || !hasLiveUses(GV))
      continue;
    if (!GV.isDeclaration() &&
        (GV.hasLocalLinkage() || GV.hasAtLeastLocalUnnamedAddr()))
      continue;
    Callback(static_cast<GlobalValue &>(GV));
  }
}

inline uint64_t hashImportName(uint64_t Hash, llvm::StringRef Name) {
  return llvm::stable_hash_combine(Hash, llvm::xxh3_64bits(Name));
}

} // namespace autojit
