#include "TPDEBackends.h"

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MD5.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
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
      errs() << "autojit-plugin: Processing module " << M.getName() << "\n";
    }

    // Collect all functions to process
    std::unordered_set<std::string> FunctionsToKeepStatic;
    StringMap<GlobalValue::GUID> FunctionsToLazify;
    std::unique_ptr<Module> LazyM = CloneModule(M);

    for (Function &F : *LazyM) {
      if (F.isDeclaration())
        continue;
      auto ModName = M.getName();
      auto FuncName = F.getName();
      if (lazifyFunction(F)) {
        auto FuncGUID = uniqueGUID(ModName, FuncName);
        FunctionsToLazify[FuncName] = FuncGUID;
        F.setName(guidToFnName(FuncGUID));
      } else {
        FunctionsToKeepStatic.insert(F.getName().str());
        F.dropAllReferences();
        F.deleteBody();
        if (LLVM_UNLIKELY(AutoJITDebug)) {
          errs() << "autojit-plugin: Skip " << F.getName() << "\n";
        }
      }
    }

    // If no functions to process, return early
    if (FunctionsToLazify.empty())
      return PreservedAnalyses::all();

    // Delete list of static inits and then initializers themselves
    if (GlobalVariable *Ctors = LazyM->getNamedGlobal("llvm.global_ctors")) {
      Ctors->eraseFromParent();
    }
    if (GlobalVariable *Dtors = LazyM->getNamedGlobal("llvm.global_dtors")) {
      Dtors->eraseFromParent();
    }
    for (const std::string &FuncName : FunctionsToKeepStatic) {
      Function *F = LazyM->getFunction(FuncName);
      F->eraseFromParent();
    }

    // Export internal global values to runtime functions
    for (GlobalVariable &LazyGV : LazyM->globals()) {
      if (LazyGV.hasAtLeastLocalUnnamedAddr()) {
        if (LLVM_UNLIKELY(AutoJITDebug))
          dbgs() << "Skip global variable: " << LazyGV.getName() << "\n";
        continue;
      }
      if (!LazyGV.hasExternalLinkage()) {
        // FIXME: ORC assertion: Resolving symbol with incorrect flags
        StringRef OriginalName = LazyGV.getName();
        if (GlobalVariable *StaticGV =
                M.getGlobalVariable(OriginalName, true)) {
          std::string NewName =
              (OriginalName + "_autojit_module_" + getModuleGUID(*LazyM)).str();
          StaticGV->setLinkage(GlobalValue::ExternalLinkage);
          StaticGV->setName(NewName);
          LazyGV.setName(NewName);
          if (LLVM_UNLIKELY(AutoJITDebug)) {
            dbgs() << "Promote linkage for global variable: " << OriginalName
                   << " --> " << NewName << "\n";
          }
        } else {
          errs() << "Failed to find global variable in static module: "
                 << OriginalName << "\n";
          exit(1);
        }
      }
      if (LazyGV.hasInitializer())
        LazyGV.setInitializer(nullptr);
      LazyGV.setLinkage(GlobalValue::ExternalLinkage);
      LazyGV.setDSOLocal(false);
    }

    // Save all original functions to one file
    std::string FilePath = saveModule(*LazyM, "");

    // Declare the runtime function __llvm_autojit_materialize
    // Updated signature: void __llvm_autojit_materialize(char* func_name, char*
    // bitcode_path, void** func_ptr_addr)
    LLVMContext &Context = M.getContext();
    FunctionType *MaterializeFT = FunctionType::get(
        Type::getVoidTy(Context),
        {PointerType::get(Context, 0)}, // Function GUID in, pointer address out
        false);

    FunctionCallee MaterializeFunc =
        M.getOrInsertFunction("__llvm_autojit_materialize", MaterializeFT);

    // Declare the runtime function __llvm_autojit_register
    FunctionType *RegisterFT = FunctionType::get(
        Type::getVoidTy(Context), {PointerType::getUnqual(Context)}, // FilePath
        false);

    FunctionCallee RegisterFunc =
        M.getOrInsertFunction("__llvm_autojit_register", RegisterFT);

    // Create global string for file path
    Constant *FilePathConstant =
        ConstantDataArray::getString(Context, FilePath);
    GlobalVariable *FilePathGV = new GlobalVariable(
        M, FilePathConstant->getType(), true, GlobalValue::PrivateLinkage,
        FilePathConstant, "__llvm_autojit_lazy_file");
    FilePathGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    for (const auto &[FuncName, FuncGUID] : FunctionsToLazify) {
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Lazify function " << FuncName << "\n";
      }

      // Create a global function pointer for this function
      Function *F = M.getFunction(FuncName);
      //F->setName(guidToFnName(FuncGUID));
      PointerType *FuncPtrType = PointerType::getUnqual(Context);
      GlobalVariable *FuncPtrGV = new GlobalVariable(
          M, FuncPtrType, false, GlobalValue::InternalLinkage,
          ConstantPointerNull::get(FuncPtrType),
          "__autojit_ptr_" + F->getName());

      // Clear the function body
      F->deleteBody();

      // Create new entry block with patchable trampoline
      BasicBlock *EntryBB = BasicBlock::Create(Context, "entry", F);
      IRBuilder<> Builder(EntryBB);

      // Load the function pointer
      Value *FuncPtr = Builder.CreateLoad(FuncPtrType, FuncPtrGV, "func_ptr");

      // Check if function pointer is null (not yet materialized)
      Value *IsNull =
          Builder.CreateICmpEQ(FuncPtr, ConstantPointerNull::get(FuncPtrType));

      // Create basic blocks for materialize and call paths
      BasicBlock *MaterializeBB = BasicBlock::Create(Context, "materialize", F);
      BasicBlock *CallBB = BasicBlock::Create(Context, "call", F);

      Builder.CreateCondBr(IsNull, MaterializeBB, CallBB);

      // Materialize block: call runtime to materialize function
      Builder.SetInsertPoint(MaterializeBB);

      // Create global string for function name
      //GlobalVariable *FuncNameGV = Builder.CreateGlobalString(F->getName());
      //Value *FuncNamePtr = Builder.CreateConstGEP2_32(
      //    FuncNameGV->getValueType(), FuncNameGV, 0, 0);
      //
      //// Get pointer to file path string
      //Value *FilePathPtr = Builder.CreateConstGEP2_32(
      //    FilePathGV->getValueType(), FilePathGV, 0, 0);

      Value *V64  = ConstantInt::get(Type::getInt64Ty(Context), FuncGUID);
      Value *VPtr = Builder.CreateIntToPtr(V64, PointerType::getUnqual(Context));
      Builder.CreateStore(VPtr, FuncPtrGV);

      // Get pointer to the function pointer global for patching
      Value *FuncPtrAddr = Builder.CreateBitCast(
          FuncPtrGV, PointerType::getUnqual(PointerType::getUnqual(Context)));

      // Call the materialize function with function name, file path, and
      // function pointer address
      Builder.CreateCall(MaterializeFunc, {FuncPtrAddr});

      // Reload the function pointer (should be patched by runtime)
      Value *MaterializedPtr =
          Builder.CreateLoad(FuncPtrType, FuncPtrGV, "materialized_ptr");

      Builder.CreateBr(CallBB);

      // Call block: call the actual function (either materialized or reloaded)
      Builder.SetInsertPoint(CallBB);

      PHINode *ActualPtr = Builder.CreatePHI(FuncPtrType, 2, "actual_ptr");
      ActualPtr->addIncoming(FuncPtr, EntryBB);
      ActualPtr->addIncoming(MaterializedPtr, MaterializeBB);

      // Collect function arguments
      SmallVector<Value *, 8> Args;
      for (Argument &Arg : F->args()) {
        Args.push_back(&Arg);
      }

      // Call the function through the pointer
      CallInst *Call =
          Builder.CreateCall(F->getFunctionType(), ActualPtr, Args);
      Call->setTailCall(true);

      // Create appropriate return instruction
      if (F->getReturnType()->isVoidTy()) {
        Builder.CreateRetVoid();
      } else {
        Builder.CreateRet(Call);
      }
    }

    // Register the lazy module from the static initializer
    FunctionType *InitFT =
        FunctionType::get(Type::getVoidTy(Context), {}, false);
    StringRef SourceFile = llvm::sys::path::filename(M.getSourceFileName());
    Function *InitFunc = Function::Create(
        InitFT, GlobalValue::InternalLinkage,
        Twine("_GLOBAL__sub_I_") + SourceFile + "_llvm_autojit_init", M);
    InitFunc->setSection(".text.startup");

    // Create function body
    BasicBlock *InitBB = BasicBlock::Create(Context, "entry", InitFunc);
    IRBuilder<> InitBuilder(InitBB);

    // Get pointer to file path string
    Value *FilePathPtr = InitBuilder.CreateConstGEP2_32(
        FilePathGV->getValueType(), FilePathGV, 0, 0);

    // Call __llvm_autojit_register with the file path
    InitBuilder.CreateCall(RegisterFunc, {FilePathPtr});
    InitBuilder.CreateRetVoid();

    // Add the initializer to the global constructor list
    appendToGlobalCtors(M, InitFunc, 65535);
    appendToUsed(M, InitFunc);

    InitFunc->addFnAttr(Attribute::NoUnwind);

    if (LLVM_UNLIKELY(AutoJITDebug))
      saveModule(M, "_static");

    return PreservedAnalyses::none();
  }

private:
  static bool lazifyFunction(Function &F) {
    if (F.hasAvailableExternallyLinkage())
      return false;
    StringRef FuncName = F.getName();
    assert(FuncName != "__llvm_autojit_materialize" && "reserved name");
    if (FuncName.starts_with("_GLOBAL__sub_"))
      return false;
    if (FuncName.starts_with("__cxx_global_var_init"))
      return false;
    if (FuncName.starts_with("_ZN__"))
      return false;
    return true;
  }

  std::string generateGUID(const std::string &SourcePath) {
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

  std::string getModuleGUID(const Module &M) {
    // Get the original source file path from the module
    std::string SourcePath = M.getName().str();
    if (SourcePath.empty()) {
      errs() << "autojit-plugin error: Invalid source path in module: "
             << SourcePath << "\n";
      exit(1);
    }

    return generateGUID(SourcePath);
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
