#include "TPDEBackends.h"

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Transforms/IPO/GlobalDCE.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
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
    if (M.getNamedValue("__llvm_autojit_register") ||
        M.getNamedValue("__llvm_autojit_materialize")) {
      errs() << "autojit-plugin: Skipping module " << M.getName() << "\n";
      return PreservedAnalyses::all();
    }

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      errs() << "autojit-plugin: Processing module " << M.getName() << "\n";
    }

    // Local definitions get exposed and must not collide
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

    // Save original module to disk
    std::string FilePath = saveModule(M, "");

    LLVMContext &Context = M.getContext();
    FunctionType *MaterializeFT = FunctionType::get(
        Type::getVoidTy(Context),
        {PointerType::get(Context, 0)}, // Function GUID in, pointer address out
        false);

    FunctionCallee MaterializeFunc =
        M.getOrInsertFunction("__llvm_autojit_materialize", MaterializeFT);

    auto ModName = M.getName();
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      if (isStaticInit(F)) {
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Keep static init " << F.getName() << "\n";
        }
        continue;
      }
      // Symbols with hidden visibility seem to fall in the same category, but technically they are still in the ABI.
      if (F.hasLocalLinkage()) {
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Drop " << F.getName() << "\n";
        }
        continue;
      }
      if (F.hasAvailableExternallyLinkage()) {
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Keep " << F.getName() << " (dupe for cross-module inlining)\n";
        }
        continue;
      }

      appendToUsed(M, &F);
      auto FuncName = F.getName();
      auto FuncGUID = uniqueGUID(ModName, FuncName);
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Lazify function " << FuncName << " as "
               << guidToFnName(FuncGUID) << "\n";
      }

      PointerType *FuncPtrType = PointerType::getUnqual(Context);
      GlobalVariable *FuncPtrGV = new GlobalVariable(
          M, FuncPtrType, false, GlobalValue::InternalLinkage,
          ConstantPointerNull::get(FuncPtrType),
          "__autojit_ptr_" + F.getName());
      F.dropAllReferences();

      // Replace body with patchable trampoline
      BasicBlock *EntryBB = BasicBlock::Create(Context, "entry", &F);
      IRBuilder<> Builder(EntryBB);

      Value *FuncPtr = Builder.CreateLoad(FuncPtrType, FuncPtrGV, "func_ptr");
      Value *IsNull =
          Builder.CreateICmpEQ(FuncPtr, ConstantPointerNull::get(FuncPtrType));

      // Prepare materialize and call paths
      BasicBlock *MaterializeBB = BasicBlock::Create(Context, "materialize", &F);
      BasicBlock *CallBB = BasicBlock::Create(Context, "call", &F);
      Builder.CreateCondBr(IsNull, MaterializeBB, CallBB);

      // Materialize block calls runtime: GUID in, ptr out
      Builder.SetInsertPoint(MaterializeBB);
      Value *V64  = ConstantInt::get(Type::getInt64Ty(Context), FuncGUID);
      Value *VPtr = Builder.CreateIntToPtr(V64, PointerType::getUnqual(Context));
      Builder.CreateStore(VPtr, FuncPtrGV);
      Value *FuncPtrAddr = Builder.CreateBitCast(
          FuncPtrGV, PointerType::getUnqual(PointerType::getUnqual(Context)));
      Builder.CreateCall(MaterializeFunc, {FuncPtrAddr});
      Value *MaterializedPtr =
          Builder.CreateLoad(FuncPtrType, FuncPtrGV, "materialized_ptr");
      Builder.CreateBr(CallBB);

      // Call block calls actual function through ptr and returns
      Builder.SetInsertPoint(CallBB);
      PHINode *ActualPtr = Builder.CreatePHI(FuncPtrType, 2, "actual_ptr");
      ActualPtr->addIncoming(FuncPtr, EntryBB);
      ActualPtr->addIncoming(MaterializedPtr, MaterializeBB);
      SmallVector<Value *, 8> Args;
      for (Argument &Arg : F.args())
        Args.push_back(&Arg);
      CallInst *Call = Builder.CreateCall(F.getFunctionType(), ActualPtr, Args);
      Call->setTailCall(true);
      if (F.getReturnType()->isVoidTy()) {
        Builder.CreateRetVoid();
      } else {
        Builder.CreateRet(Call);
      }
    }

    // Add static initializer that registers lazy file path
    FunctionType *InitFT =
        FunctionType::get(Type::getVoidTy(Context), {}, false);
    StringRef SourceFile = llvm::sys::path::filename(M.getSourceFileName());
    Function *InitFunc = Function::Create(
        InitFT, GlobalValue::InternalLinkage,
        Twine("_GLOBAL__sub_I_") + SourceFile + "_llvm_autojit_init", M);
    InitFunc->setSection(".text.startup");
    InitFunc->addFnAttr(Attribute::NoUnwind);

    BasicBlock *InitBB = BasicBlock::Create(Context, "entry", InitFunc);
    IRBuilder<> InitBuilder(InitBB);
    FunctionType *RegisterFT = FunctionType::get(
        Type::getVoidTy(Context), {PointerType::getUnqual(Context)},
        false);
    FunctionCallee RegisterFunc =
        M.getOrInsertFunction("__llvm_autojit_register", RegisterFT);

    Constant *FilePathConstant =
        ConstantDataArray::getString(Context, FilePath);
    GlobalVariable *FilePathGV = new GlobalVariable(
        M, FilePathConstant->getType(), true, GlobalValue::PrivateLinkage,
        FilePathConstant, "__llvm_autojit_lazy_file");
    FilePathGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    Value *FilePathPtr = InitBuilder.CreateConstGEP2_32(
        FilePathGV->getValueType(), FilePathGV, 0, 0);

    InitBuilder.CreateCall(RegisterFunc, {FilePathPtr});
    InitBuilder.CreateRetVoid();

    // Use runtime library priority so that all modules are registered before
    // we run the first user function.
    appendToGlobalCtors(M, InitFunc, 100);
    appendToUsed(M, InitFunc);

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
    std::string SourcePath = M.getName().str();
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
};

} // end anonymous namespace

namespace llvm {

LLVM_ABI Target &getTheX86_32Target();
LLVM_ABI Target &getTheX86_64Target();

} // namespace llvm

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
#if defined(AUTOJIT_ENABLE_TPDE)
  RegisterTargetMachine<X86TargetMachineTPDE> X(getTheX86_32Target());
  RegisterTargetMachine<X86TargetMachineTPDE> Y(getTheX86_64Target());
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
