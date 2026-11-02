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
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "common/ImportTable.h"
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

    if (M.getNamedValue("__llvm_autojit_register2") ||
        M.getNamedValue("__llvm_autojit_materialize")) {
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
      // TODO: The assembler, emits 32-bit relocations for DSO-locals, which
      // will be out-of-range for our JITed code. The verifier prevents us from
      // removing the flag in some cases though.
      if (GV.hasDefaultVisibility() || GV.hasExternalWeakLinkage())
        GV.setDSOLocal(false);
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
    uint64_t ImportsHash = 0;
    autojit::forEachImport(M, [&](GlobalValue &GV) {
      Imports.push_back(&GV);
      ImportsHash = autojit::hashImportName(ImportsHash, GV.getName());
    });

    // Save module for function importing at runtime
    M.setModuleIdentifier(FileStem);
    std::string FilePath = saveModule(M, FileStem + FileExt);

    // The runtime caches the compiled lazy module. It must not reuse it with
    // the new lazy module.
    sys::fs::remove(FileStem + ".o");

    // All further changes only affect static code
    Type *VoidTy = Type::getVoidTy(Context);
    PointerType *FnPtrTy = PointerType::get(Context, 0);
    FunctionType *MaterializeFnTy = FunctionType::get(
        FnPtrTy, {FnPtrTy, Type::getInt64Ty(Context)}, false);
    FunctionCallee MaterializeFn =
        M.getOrInsertFunction("__llvm_autojit_materialize", MaterializeFnTy);

    for (Function *F : LazifyFns) {
      auto FnName = F->getName();
      auto FnGUID = uniqueGUID(M.getSourceFileName(), F);
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Lazify function " << FnName << " as "
               << guidToFnName(FnGUID) << "\n";
      }
      // TODO: Hidden definitions generate no (observable) symbols in the static
      // binary, but they are part of the linker-visible ABI of the object file.
      // The visibility change below changes the ABI. We could avoid this by
      // adding module-specific, externally visibile functions instead, that
      // forward calls to the hidden one. However, it has signifcant impact on
      // link-time and run-time as well, which is the bigger issue long-term.
      if (F->hasHiddenVisibility()) {
        // These symbols generate static function frames and we want all calls
        // to run through it, because they might be touched by the linker (it
        // does deduplication for link-once function for example). As long as
        // dlsym is the only way for AutoJIT to find static function frames, we
        // must make sure they go into the dynamic symbol table.
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Set hidden function to default visibility "
                 << F->getName() << "\n";
        }
        F->setVisibility(GlobalValue::DefaultVisibility);
        F->setDSOLocal(false);
      }

      lazifyFn(F, FnGUID, MaterializeFn);
    }

    // Add static initializer that registers lazy file path
    FunctionType *InitFnTy = FunctionType::get(VoidTy, {}, false);
    StringRef SourceFile = sys::path::filename(M.getSourceFileName());
    Function *InitFn = Function::Create(
        InitFnTy, GlobalValue::InternalLinkage,
        Twine("_GLOBAL__sub_I_") + SourceFile + "_llvm_autojit_init", M);
    InitFn->setSection(".text.startup");
    InitFn->addFnAttr(Attribute::NoUnwind);

    BasicBlock *InitBB = BasicBlock::Create(Context, "entry", InitFn);
    IRBuilder<> InitBuilder(InitBB);
    FunctionType *RegisterFnTy =
        FunctionType::get(VoidTy, {FnPtrTy, FnPtrTy}, false);
    FunctionCallee RegisterFn =
        M.getOrInsertFunction("__llvm_autojit_register2", RegisterFnTy);

    Constant *FilePathConstant =
        ConstantDataArray::getString(Context, FilePath);
    GlobalVariable *FilePathGV = new GlobalVariable(
        M, FilePathConstant->getType(), true, GlobalValue::PrivateLinkage,
        FilePathConstant, "__llvm_autojit_lazy_file");
    FilePathGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Value *FilePathPtr = InitBuilder.CreateConstGEP2_32(
        FilePathGV->getValueType(), FilePathGV, 0, 0);

    GlobalVariable *ImportTable = emitImportTable(M, Imports, ImportsHash);
    InitBuilder.CreateCall(RegisterFn, {FilePathPtr, ImportTable});
    InitBuilder.CreateRetVoid();

    // Use runtime library priority so that all modules are registered before
    // we run the first user function.
    appendToGlobalCtors(M, InitFn, 100);

    // Add all at once: each call rebuilds the entire llvm.used array
    SmallVector<GlobalValue *, 16> Used(LazifyFns.begin(), LazifyFns.end());
    Used.push_back(InitFn);
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

  std::string saveModule(const Module &M, Twine Path) {
    std::string FilePath = Path.str();

    // Save to temporary file
    std::error_code EC;
    raw_fd_ostream OS(FilePath, EC, sys::fs::OF_None);
    if (EC) {
      errs() << "autojit-plugin error: Failed to save " << M.getName()
             << " module: " << EC.message() << "\n";
      exit(1);
    }

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      // Output LLVM IR as text
      M.print(OS, nullptr);
      errs() << "autojit-plugin: " << FilePath << " (source: " << M.getName()
             << ")\n";
    } else {
      // Output bitcode
      WriteBitcodeToFile(M, OS);
    }

    return FilePath;
  }

  // Emit the import table (see common/ImportTable.h). Each entry is a 32-bit
  // offset from the entry to its target. For symbols that might not be local
  // to the linked image, we point to a GOT-equivalent slot that the backend
  // folds into a GOT reference. This adds no dynamic relocations for symbols in
  // the image and it shares GOT entries with regular code.
  static GlobalVariable *emitImportTable(Module &M,
                                         ArrayRef<GlobalValue *> Imports,
                                         uint64_t Hash) {
    LLVMContext &Ctx = M.getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    PointerType *PtrTy = PointerType::get(Ctx, 0);
    unsigned NumEntries = Imports.size();
    ArrayType *EntriesTy = ArrayType::get(I32Ty, NumEntries);
    ArrayType *IndirectTy =
        ArrayType::get(Type::getInt8Ty(Ctx), (NumEntries + 7) / 8);
    StructType *TableTy =
        StructType::get(Ctx, {I32Ty, I32Ty, I64Ty, EntriesTy, IndirectTy});

    auto *Table = new GlobalVariable(M, TableTy, true,
                                     GlobalValue::PrivateLinkage, nullptr,
                                     "__llvm_autojit_imports");
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
        TableTy, {ConstantInt::get(I32Ty, AUTOJIT_IMPORT_TABLE_VERSION),
                  ConstantInt::get(I32Ty, NumEntries),
                  ConstantInt::get(I64Ty, Hash),
                  ConstantArray::get(EntriesTy, Entries),
                  ConstantDataArray::get(Ctx, Indirect)}));
    return Table;
  }

  void lazifyFn(Function *F, GlobalValue::GUID FnGUID, FunctionCallee MaterializeFn) {
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
    Value *MaterializedPtr =
        Builder.CreateCall(MaterializeFn, {FnPtr, Guid}, "materialized_ptr");
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
    Call->setTailCall(true);
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
