#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MD5.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/xxhash.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "common/LazyModule.h"
#include "common/Imports.h"

#if defined(AUTOJIT_ENABLE_TPDE)
#include "TPDEBackends.h"
#endif

#include <algorithm>
#include <regex>
#include <string>
#include <unordered_set>

using namespace llvm;

static cl::opt<bool> AutoJITDebug(
    "autojit-debug", cl::init(false), cl::Hidden,
    cl::desc("Enable AutoJIT debug mode - output .ll files instead of .bc"));

namespace {

static GlobalValue::GUID uniqueGUID(Twine ModName, Function *F) {
  if (F->hasLinkOnceLinkage())
    return MD5Hash(F->getName());
  std::string UniqueName = (ModName + ":" + F->getName()).str();
  return MD5Hash(UniqueName);
}

static std::string guidToFnName(GlobalValue::GUID Guid) {
  std::string Buffer;
  raw_string_ostream OS(Buffer);
  OS << "__autojit_fn_" << Guid;
  return OS.str();
}

struct AutoJITPass : public PassInfoMixin<AutoJITPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    std::string GUID = getModuleGUID(M);
    std::string FileStem = "/tmp/autojit_" + GUID;
    StringRef FileExt = AutoJITDebug ? ".ll" : ".bc";

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      saveModule(M, FileStem + "_incoming" + FileExt);
    }

    if (M.getNamedValue("__llvm_autojit_materialize")) {
      errs() << "autojit-plugin: Skipping module " << M.getName() << " (uses reserved __llvm_autojit names)\n";
      return PreservedAnalyses::all();
    }

    LLVMContext &Context = M.getContext();
    PointerType *PtrTy = PointerType::get(Context, 0);
    if (Intrinsic::getDeclarationIfExists(&M, Intrinsic::threadlocal_address, {PtrTy})) {
      errs() << "autojit-plugin: Skipping module " << M.getName() << " (thread-local storage not yet supported)\n";
      return PreservedAnalyses::all();
    }

    // Find functions that need trampolines
    SmallVector<Function *, 16> LazifyFns;
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      if (autojit::isStaticInit(F))
        continue;
      if (F.hasLocalLinkage()) {
        continue;
      }
      if (F.hasAvailableExternallyLinkage())
        continue;

      LazifyFns.push_back(&F);
    }

    if (LazifyFns.empty()) {
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Skipping module " << M.getName() << " (no functions to lazify)\n";
      }
      return PreservedAnalyses::all();
    }

    // From here on we apply modifications
    if (LLVM_UNLIKELY(AutoJITDebug)) {
      errs() << "autojit-plugin: Processing module " << M.getName() << "\n";
    }

    // Local definitions get exposed and must not collide. This affects both,
    // static code and lazy code.
    std::string UniquePostfix = "_autojit_module_" + getModuleGUID(M);

    for (GlobalVariable &GV : M.globals()) {
      if (GV.hasAtLeastLocalUnnamedAddr()) {
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Keep variable " << GV.getName() << "\n";
        }
        continue;
      }
      if (GV.hasLocalLinkage()) {
        std::string NewName = (GV.getName() + UniquePostfix).str();
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Promote variable " << GV.getName()
                 << " as " << NewName << "\n";
        }
        GV.setName(NewName);
        GV.setLinkage(GlobalValue::ExternalLinkage);
        continue;
      }
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Keep variable " << GV.getName() << "\n";
      }
    }

    // Collect the symbols that lazy code imports from static code. We must do
    // this on the same IR that we save: the runtime repeats it on the loaded
    // module and matches the entries in our import table by index.
    SmallVector<GlobalValue *, 32> Imports;
    autojit::forEachImport(M, [&](GlobalValue &GV) { Imports.push_back(&GV); });

    // Save module for function importing at runtime
    M.setModuleIdentifier(FileStem);
    uint64_t Hash;
    std::string FilePath = saveModule(M, FileStem + FileExt, &Hash);

    // All further changes only affect static code
    GlobalVariable *LazyModule =
        emitLazyModule(M, Imports, Hash, FilePath);
    FunctionType *MaterializeFnTy = FunctionType::get(
        PtrTy, {PtrTy, Type::getInt64Ty(Context), PtrTy}, false);
    FunctionCallee MaterializeFn =
        M.getOrInsertFunction("__llvm_autojit_materialize", MaterializeFnTy);

    for (Function *F : LazifyFns) {
      auto FnName = F->getName();
      auto FnGUID = uniqueGUID(M.getSourceFileName(), F);
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Lazify function " << FnName << " as "
               << guidToFnName(FnGUID) << "\n";
      }
      lazifyFn(F, FnGUID, MaterializeFn, LazyModule);
    }

    // Add all at once: each call rebuilds the entire llvm.used array
    SmallVector<GlobalValue *, 16> Used(LazifyFns.begin(), LazifyFns.end());
    appendToUsed(M, Used);

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      saveModule(M, FileStem + "_static" + FileExt);
    }

    return PreservedAnalyses::none();
  }

private:
  std::string getModuleGUID(const Module &M) {
    // Get the original source file path from the module
    std::string SourcePath = M.getSourceFileName();
    if (SourcePath.empty()) {
      errs() << "autojit-plugin error: Invalid source path in module: "
             << SourcePath << "\n";
      exit(1);
    }

    // Generate MD5 hash of the source path
    MD5 Hasher;
    Hasher.update(SourcePath);
    MD5::MD5Result Hash;
    Hasher.final(Hash);

    // Convert to hex string
    SmallString<32> Result;
    MD5::stringifyResult(Hash, Result);
    return Result.str().str();
  }

  std::string saveModule(const Module &M, Twine Path,
                         uint64_t *Hash = nullptr) {
    std::string FilePath = Path.str();

    SmallVector<char, 0> Buffer;
    raw_svector_ostream BufferOS(Buffer);
    if (LLVM_UNLIKELY(AutoJITDebug)) {
      // Output LLVM IR as text
      M.print(BufferOS, nullptr);
      errs() << "autojit-plugin: " << FilePath << " (source: " << M.getName()
             << ")\n";
    } else {
      // Output bitcode
      WriteBitcodeToFile(M, BufferOS);
    }

    // The runtime identifies the contents of the file by this hash
    if (Hash)
      *Hash = xxh3_64bits(arrayRefFromStringRef(BufferOS.str()));

    std::error_code EC;
    raw_fd_ostream OS(FilePath, EC, sys::fs::OF_None);
    if (EC) {
      errs() << "autojit-plugin error: Failed to save " << M.getName()
             << " module: " << EC.message() << "\n";
      exit(1);
    }
    OS << BufferOS.str();
    return FilePath;
  }

  // Emit the lazy module descriptor (see common/LazyModule.h). Each import
  // entry is a 32-bit offset from the entry to its target. For symbols that
  // might not be local to the linked image, we point to a GOT-equivalent slot
  // that the backend folds into a GOT reference. This adds no dynamic
  // relocations for symbols in the image and it shares GOT entries with
  // regular code.
  static GlobalVariable *emitLazyModule(Module &M,
                                        ArrayRef<GlobalValue *> Imports,
                                        uint64_t Hash, StringRef FilePath) {
    LLVMContext &Ctx = M.getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    PointerType *PtrTy = PointerType::get(Ctx, 0);
    unsigned NumEntries = Imports.size();
    ArrayType *EntriesTy = ArrayType::get(I32Ty, NumEntries);
    ArrayType *IndirectTy =
        ArrayType::get(Type::getInt8Ty(Ctx), (NumEntries + 7) / 8);
    Constant *Path = ConstantDataArray::getString(Ctx, FilePath);
    StructType *TableTy = StructType::get(
        Ctx, {I32Ty, I32Ty, I64Ty, EntriesTy, IndirectTy, Path->getType()});

    auto *Table = new GlobalVariable(M, TableTy, true,
                                     GlobalValue::PrivateLinkage, nullptr,
                                     "__llvm_autojit_module");
    Table->setAlignment(Align(8));

    SmallVector<Constant *, 32> Entries;
    Entries.reserve(NumEntries);
    SmallVector<uint8_t, 8> Indirect((NumEntries + 7) / 8, 0);
    Constant *Zero = ConstantInt::get(I32Ty, 0);
    Constant *EntriesIdx = ConstantInt::get(I32Ty, 3);
    for (unsigned I = 0; I < NumEntries; I += 1) {
      GlobalValue *GV = Imports[I];
      Constant *Target = GV;
      if (!GV->isDSOLocal() || GV->hasExternalWeakLinkage()) {
        auto *Slot = new GlobalVariable(M, PtrTy, true,
                                        GlobalValue::PrivateLinkage, GV,
                                        "__llvm_autojit_got");
        Slot->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        Target = Slot;
        Indirect[I / 8] |= 1 << (I % 8);
      }
      Constant *Idx[] = {Zero, EntriesIdx, ConstantInt::get(I32Ty, I)};
      Constant *Place =
          ConstantExpr::getInBoundsGetElementPtr(TableTy, Table, Idx);
      Constant *Offset =
          ConstantExpr::getSub(ConstantExpr::getPtrToInt(Target, I64Ty),
                               ConstantExpr::getPtrToInt(Place, I64Ty));
      Entries.push_back(ConstantExpr::getTrunc(Offset, I32Ty));
    }

    Table->setInitializer(ConstantStruct::get(
        TableTy, {ConstantInt::get(I32Ty, AUTOJIT_LAZY_MODULE_VERSION),
                  ConstantInt::get(I32Ty, NumEntries),
                  ConstantInt::get(I64Ty, Hash),
                  ConstantArray::get(EntriesTy, Entries),
                  ConstantDataArray::get(Ctx, Indirect), Path}));
    return Table;
  }

  void lazifyFn(Function *F, GlobalValue::GUID FnGUID,
                FunctionCallee MaterializeFn, GlobalVariable *LazyModule) {
    Module *M = F->getParent();
    LLVMContext &Context = M->getContext();
    PointerType *FnPtrTy = PointerType::get(Context, 0);

    GlobalVariable *FnPtr =
        new GlobalVariable(*M, FnPtrTy, false, GlobalValue::InternalLinkage,
                           ConstantPointerNull::get(FnPtrTy),
                           "__llvm_autojit_ptr_" + F->getName());
    F->dropAllReferences();

    // Replace body with patchable trampoline
    BasicBlock *EntryBB = BasicBlock::Create(Context, "entry", F);
    IRBuilder<> Builder(EntryBB);

    // The slot holds either null or the final address. The runtime stores it
    // with release semantics once the function is materialized.
    LoadInst *ExistingFnPtr = Builder.CreateAlignedLoad(
        FnPtrTy, FnPtr, M->getDataLayout().getPointerABIAlignment(0),
        "existing_ptr");
    ExistingFnPtr->setAtomic(AtomicOrdering::Acquire);
    Value *IsNull = Builder.CreateICmpEQ(ExistingFnPtr,
                                         ConstantPointerNull::get(FnPtrTy));

    // Prepare materialize and call paths
    BasicBlock *MaterializeBB = BasicBlock::Create(Context, "materialize", F);
    BasicBlock *CallBB = BasicBlock::Create(Context, "call", F);
    Builder.CreateCondBr(IsNull, MaterializeBB, CallBB);

    // Materialize block calls the runtime, which also fills the slot
    Builder.SetInsertPoint(MaterializeBB);
    Value *Guid = ConstantInt::get(Type::getInt64Ty(Context), FnGUID);
    Value *MaterializedPtr = Builder.CreateCall(
        MaterializeFn, {FnPtr, Guid, LazyModule}, "materialized_ptr");
    Builder.CreateBr(CallBB);

    // Call block calls actual function through ptr and returns
    Builder.SetInsertPoint(CallBB);
    PHINode *ImplPtr = Builder.CreatePHI(FnPtrTy, 2, "impl_ptr");
    ImplPtr->addIncoming(ExistingFnPtr, EntryBB);
    ImplPtr->addIncoming(MaterializedPtr, MaterializeBB);
    SmallVector<Value *, 8> Args;
    for (Argument &Arg : F->args())
      Args.push_back(&Arg);
    CallInst *Call = Builder.CreateCall(F->getFunctionType(), ImplPtr, Args);

    // Forward arguments exactly as we received them, e.g. structs passed
    // byval must be passed byval again.
    AttributeList Attrs = F->getAttributes();
    SmallVector<AttributeSet, 8> ParamAttrs;
    for (unsigned I = 0; I < F->arg_size(); I += 1)
      ParamAttrs.push_back(Attrs.getParamAttrs(I));
    Call->setAttributes(AttributeList::get(Context, AttributeSet(),
                                           Attrs.getRetAttrs(), ParamAttrs));
    Call->setCallingConv(F->getCallingConv());

    // Variadic arguments can only be forwarded with a guaranteed tail call
    Call->setTailCallKind(F->isVarArg() ? CallInst::TCK_MustTail
                                        : CallInst::TCK_Tail);
    if (F->getReturnType()->isVoidTy()) {
      Builder.CreateRetVoid();
    } else {
      Builder.CreateRet(Call);
    }
  }
};

} // end anonymous namespace

#if defined(AUTOJIT_ENABLE_TPDE)
namespace llvm {

LLVM_ABI Target &getTheX86_32Target() __attribute__((weak));
LLVM_ABI Target &getTheX86_64Target() __attribute__((weak));

} // namespace llvm
#endif

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  if (const char *Var = std::getenv("AUTOJIT_DEBUG")) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      AutoJITDebug = true;
  }
#if defined(AUTOJIT_ENABLE_TPDE)
  if (getTheX86_32Target && getTheX86_64Target) {
    RegisterTargetMachine<X86TargetMachineTPDE> X(getTheX86_32Target());
    RegisterTargetMachine<X86TargetMachineTPDE> Y(getTheX86_64Target());
  } else {
    errs() << "Failed to register TPDE codegen backend\n";
  }
#endif
  return {.APIVersion = LLVM_PLUGIN_API_VERSION,
          .PluginName = "AutoJIT Pass",
          .PluginVersion = "v0.1",
          .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            // Register to run automatically at the end of the module pipeline
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                  MPM.addPass(AutoJITPass());
                  MPM.addPass(GlobalDCEPass());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &PM,
                   ArrayRef<PassBuilder::PipelineElement> InnerPipeline) {
                  if (Name.lower() == "autojit") {
                    PM.addPass(AutoJITPass());
                    return true;
                  }
                  return false;
                });
          }};
}
