#pragma once

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace autojit {

inline bool isStaticInit(const llvm::Function &F) {
  llvm::StringRef FuncName = F.getName();
  // With init_priority they are named _GLOBAL__I_<priority>
  if (FuncName.starts_with("_GLOBAL__sub_") ||
      FuncName.starts_with("_GLOBAL__I_") || FuncName.starts_with("_GLOBAL__D_"))
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

/// The plugin marks functions that must stay in static code with this attribute
/// in the lazy module.
inline constexpr const char *KeepStaticAttr = "autojit-static";

/// Value of the attribute if the JIT may keep the body for inlining.
inline constexpr const char *KeepStaticWithBody = "with-body";

/// Named metadata in the lazy module with the textual pipeline for the runtime
/// and the optimization level of the compile as strings.
inline constexpr const char *PipelineMetadata = "autojit.pipeline";

/// How lazy code binds to a function that the lazy module defines.
enum class LazyBinding {
  /// Stays in static code, the lazy module imports it
  Static,
  /// Only exists as an internal copy in the lazy module. The static object only
  /// keeps it if static code uses it.
  Local,
  /// Only exists in the lazy module. No trampoline, slot or import.
  Private,
  /// Has a trampoline. Lazy code calls the definition directly and takes the
  /// address of the trampoline, so that function pointers stay stable.
  Direct,
  /// Has a trampoline and lazy code reaches it only through there, because the
  /// definition might get interposed.
  Proxy,
};

/// Label addresses only have a meaning for the code in the static object. The
/// lazy module can't get its own copy of a variable that holds them.
inline bool refersToBlockAddress(const llvm::GlobalVariable &GV) {
  using namespace llvm;
  if (!GV.hasInitializer())
    return false;
  SmallVector<const Constant *, 8> Worklist = {GV.getInitializer()};
  SmallPtrSet<const Constant *, 16> Seen;
  while (!Worklist.empty()) {
    const Constant *C = Worklist.pop_back_val();
    if (isa<BlockAddress>(C))
      return true;
    if (isa<GlobalValue>(C))
      continue;
    for (const Value *Op : C->operands())
      if (auto *Next = dyn_cast<Constant>(Op))
        if (Seen.insert(Next).second)
          Worklist.push_back(Next);
  }
  return false;
}

/// Whether the lazy module gets a copy of a variable. The address of unnamed_addr
/// variables is insignificant. All other variables are shared with the static
/// object, including local ones.
inline bool hasLazyCopy(const llvm::GlobalVariable &GV) {
  return !GV.isDeclaration() && GV.hasAtLeastLocalUnnamedAddr() &&
         !refersToBlockAddress(GV);
}

/// Whether a function has uses other than direct calls to its exact type.
inline bool hasNonCallUses(const llvm::Function &F) {
  for (const llvm::Use &U : F.uses()) {
    auto *CB = llvm::dyn_cast<llvm::CallBase>(U.getUser());
    if (!CB || !CB->isCallee(&U) ||
        CB->getFunctionType() != F.getFunctionType())
      return true;
  }
  return false;
}

/// Classifies all function definitions in a lazy module. The plugin and the
/// runtime must agree, because the import table matches entries by index. So
/// the result only depends on the saved IR.
class LazyBindings {
public:
  explicit LazyBindings(llvm::Module &M) {
    using namespace llvm;
    SmallVector<const Function *, 32> Worklist;
    // Runs in static code, including everything that it reaches
    auto IsRoot = [](const Function &F) {
      return isStaticInit(F) || F.hasFnAttribute(KeepStaticAttr);
    };

    for (Function &F : M) {
      F.removeDeadConstantUsers();
      if (F.isDeclaration())
        continue;
      if (IsRoot(F)) {
        Worklist.push_back(&F);
        continue;
      }
      if (!F.hasLocalLinkage())
        continue;
      // Functions in variable initializers are callbacks, e.g. in tables of
      // operations. A trampoline makes them lazy and gives them one address.
      // Use lists have another order after loading bitcode, so we must look at
      // all users.
      bool InList = false;
      bool InInitializer = false;
      for (const User *U : F.users()) {
        if (isa<Instruction>(U))
          continue;
        if (isCtorOrUsedList(U))
          InList = true;
        else
          InInitializer = true;
      }
      if (InList)
        Worklist.push_back(&F);
      else if (InInitializer)
        Trampolined.insert(&F);
    }

    DenseSet<const Function *> Reached(Worklist.begin(), Worklist.end());
    while (!Worklist.empty()) {
      const Function *F = Worklist.pop_back_val();
      forEachReferencedFunction(*F, [&](const Function &Callee) {
        StaticUsed.insert(&Callee);
        // These bodies might end up in static code as well
        if (!Callee.isDeclaration() && !Trampolined.contains(&Callee) &&
            (Callee.hasLocalLinkage() ||
             Callee.hasAvailableExternallyLinkage()) &&
            Reached.insert(&Callee).second)
          Worklist.push_back(&Callee);
      });
    }

    // Static and lazy code both take the address of a local function
    for (const Function *F : Reached) {
      if (!F->hasLocalLinkage() || IsRoot(*F))
        continue;
      for (const Use &U : F->uses()) {
        auto *I = dyn_cast<Instruction>(U.getUser());
        auto *CB = dyn_cast<CallBase>(U.getUser());
        if (I && !(CB && CB->isCallee(&U)) &&
            !Reached.contains(I->getFunction())) {
          Trampolined.insert(F);
          break;
        }
      }
    }
  }

  LazyBinding get(const llvm::Function &F) const {
    using namespace llvm;
    if (isStaticInit(F) || F.hasFnAttribute(KeepStaticAttr))
      return LazyBinding::Static;
    if (F.hasLocalLinkage())
      return Trampolined.contains(&F) ? LazyBinding::Direct
                                      : LazyBinding::Local;
    if (F.hasLinkOnceODRLinkage()) {
      // A trampoline in another object can't get lost: all objects that use an
      // inline function have their own copy. Other templates might be defined in
      // one source file and called from others, relying on the instantiation.
      // Clang only adds the hint when it optimizes, so with optnone we can't tell
      // and take the risk. If the comdat has other members, then objects might
      // disagree about its contents and the linker picks one.
      bool IsInline = F.hasFnAttribute(Attribute::InlineHint) ||
                      F.hasFnAttribute(Attribute::AlwaysInline) ||
                      F.hasFnAttribute(Attribute::OptimizeNone);
      bool OwnComdat =
          !F.hasComdat() || F.getComdat()->getName() == F.getName();
      if (IsInline && OwnComdat && !hasNonCallUses(F) &&
          !StaticUsed.contains(&F))
        return LazyBinding::Private;
      return LazyBinding::Direct;
    }
    if (F.hasWeakODRLinkage() || (F.hasExternalLinkage() && F.isDSOLocal()))
      return LazyBinding::Direct;
    return LazyBinding::Proxy;
  }

private:
  static bool isCtorOrUsedList(const llvm::User *U) {
    using namespace llvm;
    // Constant structs and arrays lead to the global
    SmallVector<const User *, 4> Worklist = {U};
    while (!Worklist.empty()) {
      const User *Cur = Worklist.pop_back_val();
      if (auto *GV = dyn_cast<GlobalVariable>(Cur)) {
        if (GV->getName().starts_with("llvm."))
          return true;
        continue;
      }
      if (isa<Constant>(Cur) && !isa<GlobalValue>(Cur))
        for (const User *Next : Cur->users())
          Worklist.push_back(Next);
    }
    return false;
  }

  template <typename CallbackT>
  static void forEachReferencedFunction(const llvm::Function &F,
                                        CallbackT Callback) {
    using namespace llvm;
    SmallVector<const Constant *, 8> Worklist;
    SmallPtrSet<const Constant *, 16> Seen;
    for (const BasicBlock &BB : F)
      for (const Instruction &I : BB)
        for (const Value *Op : I.operands())
          if (auto *C = dyn_cast<Constant>(Op))
            if (Seen.insert(C).second)
              Worklist.push_back(C);
    while (!Worklist.empty()) {
      const Constant *C = Worklist.pop_back_val();
      if (auto *Callee = dyn_cast<Function>(C)) {
        Callback(*Callee);
        continue;
      }
      if (isa<GlobalValue>(C))
        continue;
      for (const Value *Op : C->operands())
        if (auto *Next = dyn_cast<Constant>(Op))
          if (Seen.insert(Next).second)
            Worklist.push_back(Next);
    }
  }

  llvm::DenseSet<const llvm::Function *> StaticUsed;
  llvm::DenseSet<const llvm::Function *> Trampolined;
};

/// Visit all symbols that the lazy module imports from the host process. The
/// plugin calls this right before it saves the lazy module, and the runtime
/// calls it right after it loads the module. Both must see the same sequence,
/// because the import table in the static object matches entries by index.
///
/// Keep this in sync with AutoJIT::loadModule(): it turns each of them into a
/// declaration (or adds a declaration for it in case of function definitions).
template <typename CallbackT>
void forEachImport(llvm::Module &M, const LazyBindings &Bindings,
                   CallbackT Callback) {
  using namespace llvm;
  for (Function &F : M) {
    if (F.isIntrinsic() || !hasLiveUses(F))
      continue;
    if (!F.isDeclaration()) {
      if (F.hasAvailableExternallyLinkage()) {
        if (F.hasFnAttribute(Attribute::AlwaysInline))
          continue;
      } else {
        if (isStaticInit(F))
          continue;
        switch (Bindings.get(F)) {
        case LazyBinding::Local:
        case LazyBinding::Private:
          continue;
        case LazyBinding::Direct:
          if (!hasNonCallUses(F))
            continue;
          break;
        case LazyBinding::Static:
        case LazyBinding::Proxy:
          break;
        }
      }
    }
    Callback(static_cast<GlobalValue &>(F));
  }
  for (GlobalVariable &GV : M.globals()) {
    if (GV.getName().starts_with("llvm.") || !hasLiveUses(GV))
      continue;
    if (hasLazyCopy(GV))
      continue;
    Callback(static_cast<GlobalValue &>(GV));
  }
  for (GlobalIFunc &GI : M.ifuncs())
    if (hasLiveUses(GI))
      Callback(static_cast<GlobalValue &>(GI));
}

} // namespace autojit
