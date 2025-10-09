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

static GlobalValue::GUID uniqueGUID(Twine ModName, Twine FuncName) {
  auto UniqueName = (ModName + ":" + FuncName).str();
  return GlobalValue::getGUID(UniqueName);
}

static std::string guidToFnName(GlobalValue::GUID Guid) {
  std::string Buffer;
  raw_string_ostream OS(Buffer);
  OS << "__autojit_fn_" << Guid;
  return OS.str();
}

struct AutoJITPass : public PassInfoMixin<AutoJITPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    if (LLVM_UNLIKELY(AutoJITDebug)) {
      saveModule(M, "_incoming");
    }

    if (M.getNamedValue("__llvm_autojit_register") ||
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

    // Find functions that need trampolines
    SmallVector<Function *, 16> LazifyFns;
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      if (isStaticInit(F))
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

    // Save module for function importing at runtime
    std::string FilePath = saveModule(M, "");

    // All further changes only affect static code
    Type *VoidTy = Type::getVoidTy(Context);
    PointerType *FnPtrTy = PointerType::get(Context, 0);
    FunctionType *MaterializeFnTy = FunctionType::get(VoidTy, {FnPtrTy}, false);
    FunctionCallee MaterializeFn =
        M.getOrInsertFunction("__llvm_autojit_materialize", MaterializeFnTy);

    for (Function *F : LazifyFns) {
      auto FnName = F->getName();
      auto FnGUID = uniqueGUID(M.getSourceFileName(), FnName);
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Lazify function " << FnName << " as "
               << guidToFnName(FnGUID) << "\n";
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
    FunctionType *RegisterFnTy = FunctionType::get(VoidTy, {FnPtrTy}, false);
    FunctionCallee RegisterFn =
        M.getOrInsertFunction("__llvm_autojit_register", RegisterFnTy);

    Constant *FilePathConstant =
        ConstantDataArray::getString(Context, FilePath);
    GlobalVariable *FilePathGV = new GlobalVariable(
        M, FilePathConstant->getType(), true, GlobalValue::PrivateLinkage,
        FilePathConstant, "__llvm_autojit_lazy_file");
    FilePathGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Value *FilePathPtr = InitBuilder.CreateConstGEP2_32(
        FilePathGV->getValueType(), FilePathGV, 0, 0);

    InitBuilder.CreateCall(RegisterFn, {FilePathPtr});
    InitBuilder.CreateRetVoid();

    // Use runtime library priority so that all modules are registered before
    // we run the first user function.
    appendToGlobalCtors(M, InitFn, 100);
    appendToUsed(M, InitFn);

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      std::string FilePath = saveModule(M, "_static");
    }

    return PreservedAnalyses::none();
  }

private:
  static bool isStaticInit(const Function &F) {
    StringRef FuncName = F.getName();
    if (FuncName.starts_with("_GLOBAL__sub_"))
      return true;
    if (FuncName.starts_with("__cxx_global_var_init"))
      return true;
    return false;
  }

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

  std::string saveModule(const Module &M, StringRef Suffix) {
    std::string GUID = getModuleGUID(M);
    std::string FileExtension = AutoJITDebug ? ".ll" : ".bc";
    std::string FilePath =
        "/tmp/autojit_" + GUID + Suffix.str() + FileExtension;

    // Save to temporary file
    // TODO: Include content hash in name
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

  void lazifyFn(Function *F, GlobalValue::GUID FnGUID, FunctionCallee MaterializeFn) {
    Module *M = F->getParent();
    LLVMContext &Context = M->getContext();
    PointerType *FnPtrTy = PointerType::get(Context, 0);

    GlobalVariable *FnPtr =
        new GlobalVariable(*M, FnPtrTy, false, GlobalValue::InternalLinkage,
                           ConstantPointerNull::get(FnPtrTy),
                           "__llvm_autojit_ptr_" + F->getName());
    F->dropAllReferences();
    appendToUsed(*M, F);

    // Replace body with patchable trampoline
    BasicBlock *EntryBB = BasicBlock::Create(Context, "entry", F);
    IRBuilder<> Builder(EntryBB);

    Value *ExistingFnPtr = Builder.CreateLoad(FnPtrTy, FnPtr, "existing_ptr");
    Value *IsNull = Builder.CreateICmpEQ(ExistingFnPtr,
                                         ConstantPointerNull::get(FnPtrTy));

    // Prepare materialize and call paths
    BasicBlock *MaterializeBB = BasicBlock::Create(Context, "materialize", F);
    BasicBlock *CallBB = BasicBlock::Create(Context, "call", F);
    Builder.CreateCondBr(IsNull, MaterializeBB, CallBB);

    // Materialize block calls runtime: GUID in, ptr out
    Builder.SetInsertPoint(MaterializeBB);
    Value *V64 = ConstantInt::get(Type::getInt64Ty(Context), FnGUID);
    Value *VPtr = Builder.CreateIntToPtr(V64, FnPtrTy);
    Builder.CreateStore(VPtr, FnPtr);
    Value *FnPtrAddr =
        Builder.CreateBitCast(FnPtr, PointerType::get(FnPtrTy, 0));
    Builder.CreateCall(MaterializeFn, {FnPtrAddr});
    Value *MaterializedPtr =
        Builder.CreateLoad(FnPtrTy, FnPtr, "materialized_ptr");
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
