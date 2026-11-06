#include "AutoJITConfig.h"

#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalIFunc.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/Passes/PassBuilder.h>
#if AUTOJIT_LLVM_21
#include <llvm/Passes/PassPlugin.h>
#else
#include <llvm/Plugins/PassPlugin.h>
#endif
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Compiler.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/FileSystem.h>
#if !AUTOJIT_LLVM_21
#include <llvm/Support/IOSandbox.h>
#endif
#include <llvm/Support/CodeGen.h>
#include <llvm/Support/MD5.h>
#include <llvm/Support/SpecialCaseList.h>
#include <llvm/Support/VirtualFileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/xxhash.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include "common/LazyModule.h"
#include "common/Imports.h"

#include <dlfcn.h>

#include <algorithm>
#include <fstream>
#include <memory>
#include <regex>
#include <string>
#include <unordered_set>
#include <utility>

using namespace llvm;

static cl::opt<bool> AutoJITDebug(
    "autojit-debug", cl::init(false), cl::Hidden,
    cl::desc("Enable AutoJIT debug mode - output .ll files instead of .bc"));

static cl::opt<bool> AutoJITStaticLibFuncs(
    "autojit-static-libfuncs", cl::init(true), cl::Hidden,
    cl::desc("Keep definitions of library functions like malloc or memcpy in "
             "static code. The C library and the runtime might call them, so "
             "they must not be lazy. Also set via AUTOJIT_STATIC_LIBFUNCS "
             "environment variable."));

static cl::opt<std::string> AutoJITDir(
    "autojit-dir", cl::init("/tmp"), cl::Hidden,
    cl::desc("Directory for lazy modules (and the runtime's object cache). "
             "Also set via AUTOJIT_DIR environment variable."));

static cl::opt<std::string> AutoJITRuntime(
    "autojit-runtime", cl::init(""), cl::Hidden,
    cl::desc("Library to put on the link line through .deplibs. Defaults to "
             "the static stub next to the plugin. Also set via AUTOJIT_RUNTIME "
             "environment variable."));

static cl::opt<bool> AutoJITNoDeplibs(
    "autojit-no-deplibs", cl::init(false), cl::Hidden,
    cl::desc("Don't put the runtime on the link line through .deplibs. For "
             "links that add it explicitly, like the compiler wrappers. Also "
             "set via AUTOJIT_NO_DEPLIBS environment variable."));

static cl::opt<unsigned> AutoJITStaticThreshold(
    "autojit-static-threshold", cl::init(12), cl::Hidden,
    cl::desc("Keep leaf functions with up to this many IR instructions in "
             "static code, where they are no bigger than a trampoline and "
             "don't force a lazy module to compile. 0 disables it. Also set "
             "via AUTOJIT_STATIC_THRESHOLD environment variable."));

static cl::opt<std::string> AutoJITIgnoreList(
    "autojit-ignorelist", cl::init(""), cl::Hidden,
    cl::desc("Special case list with what must stay in static code: fun:<name> "
             "for functions and src:<path> for whole translation units. Also "
             "set via AUTOJIT_IGNORELIST environment variable."));

static cl::opt<std::string> AutoJITStats(
    "autojit-stats", cl::init(""), cl::Hidden,
    cl::desc("Append statistics for each module to this file. Also set via "
             "AUTOJIT_STATS environment variable."));

static cl::opt<std::string> AutoJITPipeline(
    "autojit-pipeline", cl::init(""), cl::Hidden,
    cl::desc("Pipeline for the runtime to run on lazy modules, instead of the "
             "one that the compiler would run on them."));

// Set while we build the pipeline to record it, so we don't add ourselves
static bool RecordingPipeline = false;

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

// Copy of TargetMachine::isLargeGlobalValue() from LLVM 21, because pass
// plugins have no access to the TargetMachine. Keep it in sync. The code model
// and large data threshold come from the module flags here. One deviation: we
// can't classify sections without TargetLoweringObjectFile, so read-only data
// with relocations counts as large, if it exceeds the threshold.
static bool isLargeGlobalValue(const GlobalValue &GVal, const Triple &TT,
                               std::optional<CodeModel::Model> CM,
                               uint64_t LargeDataThreshold) {
  if (TT.getArch() != Triple::x86_64)
    return false;

  // Remaining logic below is ELF-specific. For other object file formats where
  // the large code model is mostly used for JIT compilation, just look at the
  // code model.
  if (!TT.isOSBinFormatELF())
    return CM == CodeModel::Large;

  auto *GO = GVal.getAliaseeObject();

  // Be conservative if we can't find an underlying GlobalObject.
  if (!GO)
    return true;

  auto *GV = dyn_cast<GlobalVariable>(GO);

  auto IsPrefix = [](StringRef Name, StringRef Prefix) {
    return Name.consume_front(Prefix) && (Name.empty() || Name[0] == '.');
  };

  // Functions/GlobalIFuncs are only large under the large code model.
  if (!GV) {
    if (GO->hasSection())
      return IsPrefix(GO->getSection(), ".ltext");
    return CM == CodeModel::Large;
  }

  if (GV->isThreadLocal())
    return false;

  // An explicit code model on the variable decides about its section.
  if (auto VarCM = GV->getCodeModel()) {
    if (*VarCM == CodeModel::Small)
      return false;
    if (*VarCM == CodeModel::Large)
      return true;
  }

  // Globals in explicit sections are small, except for the standard large
  // sections.
  if (GV->hasSection()) {
    StringRef Name = GV->getSection();
    return IsPrefix(Name, ".lbss") || IsPrefix(Name, ".ldata") ||
           IsPrefix(Name, ".lrodata");
  }

  // Respect large data threshold for medium and large code models.
  if (CM == CodeModel::Medium || CM == CodeModel::Large) {
    if (!GV->getValueType()->isSized())
      return true;
    // Linker defined start/stop symbols can point to arbitrary points in the
    // binary, so treat them as large.
    if (GV->isDeclaration() && (GV->getName() == "__ehdr_start" ||
                                GV->getName().starts_with("__start_") ||
                                GV->getName().starts_with("__stop_")))
      return true;
    const DataLayout &DL = GV->getDataLayout();
    uint64_t Size = DL.getTypeAllocSize(GV->getValueType());
    return Size == 0 || Size > LargeDataThreshold;
  }

  return false;
}

// Whether a 32-bit PC-relative reference from regular data in the same object
// might not reach GV after linking. The linker places large sections far away,
// so references to them might be out of range. With the large code model, we
// don't rely on any distances.
static bool mayBeOutOfRange(const GlobalValue &GV, const Triple &TT,
                            std::optional<CodeModel::Model> CM,
                            uint64_t LargeDataThreshold) {
  if (CM == CodeModel::Large)
    return true;
  return isLargeGlobalValue(GV, TT, CM, LargeDataThreshold);
}

// Must not be skipped, e.g. for optnone functions
#if AUTOJIT_LLVM_21
struct AutoJITPass : public PassInfoMixin<AutoJITPass> {
  static bool isRequired() { return true; }
#else
struct AutoJITPass : public RequiredPassInfoMixin<AutoJITPass> {
#endif
  AutoJITPass() = default;
  AutoJITPass(PassBuilder &PB, OptimizationLevel Level)
      : PB(&PB), Level(Level) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
#if !AUTOJIT_LLVM_21
    // We write lazy modules next to the object file, not through clang's VFS
    auto BypassSandbox = sys::sandbox::scopedDisable();
#endif
    std::string GUID = getModuleGUID(M);
    std::string FileStem = getOutputDir() + "/autojit_" + GUID;
    StringRef FileExt = AutoJITDebug ? ".ll" : ".bc";

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      saveModule(M, FileStem + "_incoming" + FileExt);
    }

    // Build systems might pass the plugin twice, e.g. in CFLAGS and CPPFLAGS. The
    // second run must leave our trampolines alone.
    if (M.getNamedValue("__llvm_autojit_materialize") ||
        M.getNamedValue("__llvm_autojit_resolve") ||
        M.getNamedValue("__llvm_autojit_module")) {
      if (LLVM_UNLIKELY(AutoJITDebug))
        errs() << "autojit-plugin: Skipping module " << M.getName()
               << " (uses reserved __llvm_autojit names)\n";
      return PreservedAnalyses::all();
    }

    LLVMContext &Context = M.getContext();
    PointerType *PtrTy = PointerType::get(Context, 0);
    if (Intrinsic::getDeclarationIfExists(&M, Intrinsic::threadlocal_address, {PtrTy})) {
      errs() << "autojit-plugin: Skipping module " << M.getName() << " (thread-local storage not yet supported)\n";
      return PreservedAnalyses::all();
    }

    const SpecialCaseList *IgnoreList = getIgnoreList();
    if (IgnoreList && IgnoreList->inSection("", "src", M.getSourceFileName())) {
      if (LLVM_UNLIKELY(AutoJITDebug))
        errs() << "autojit-plugin: Skipping module " << M.getName()
               << " (in the ignore list)\n";
      return PreservedAnalyses::all();
    }

    SmallVector<Function *, 8> KeptStatic =
        markStaticFunctions(M, MAM, IgnoreList);

    // Find functions that need trampolines
    autojit::LazyBindings Bindings(M);
    writeStats(M, Bindings);
    SmallVector<Function *, 16> LazifyFns;
    SmallVector<Function *, 16> PrivateFns;
    for (Function &F : M) {
      if (F.isDeclaration() || F.hasAvailableExternallyLinkage())
        continue;
      switch (Bindings.get(F)) {
      case autojit::LazyBinding::Static:
      case autojit::LazyBinding::Local:
        break;
      case autojit::LazyBinding::Private:
        PrivateFns.push_back(&F);
        break;
      case autojit::LazyBinding::Direct:
      case autojit::LazyBinding::Proxy:
        LazifyFns.push_back(&F);
        break;
      }
    }

    if (LazifyFns.empty()) {
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Skipping module " << M.getName() << " (no functions to lazify)\n";
      }
      for (Function *F : KeptStatic)
        F->removeFnAttr(autojit::KeepStaticAttr);
      return PreservedAnalyses::all();
    }

    // From here on we apply modifications
    if (LLVM_UNLIKELY(AutoJITDebug)) {
      errs() << "autojit-plugin: Processing module " << M.getName() << "\n";
    }

    // Collect the symbols that lazy code imports from static code. We must do
    // this on the same IR that we save: the runtime repeats it on the loaded
    // module and matches the entries in our import table by index.
    SmallVector<GlobalValue *, 32> Imports;
    autojit::forEachImport(M, Bindings,
                           [&](GlobalValue &GV) { Imports.push_back(&GV); });

    // Lazy modules get their own copies of unnamed_addr variables, so they
    // aren't imports. Static code might not use them anymore, but other
    // objects might still refer to them, e.g. linkonce vtables. They must
    // stay in the static object.
    SmallVector<GlobalValue *, 8> KeepVars;
    for (GlobalVariable &GV : M.globals())
      if (autojit::hasLazyCopy(GV) && !GV.hasLocalLinkage() &&
          autojit::hasLiveUses(GV))
        KeepVars.push_back(&GV);

    // Save module for function importing at runtime
    M.setModuleIdentifier(FileStem);
    recordPipeline(M);
    uint64_t Hash;
    std::string FilePath = saveModule(M, FileStem + FileExt, &Hash);
    if (NamedMDNode *MD = M.getNamedMetadata(autojit::PipelineMetadata))
      M.eraseNamedMetadata(MD);

    // All further changes only affect static code
    GlobalVariable *LazyModule =
        emitLazyModule(M, Imports, Hash, FilePath);
    FunctionCallee MaterializeFn;
    Function *ResolverThunk = nullptr;
    for (Function *F : LazifyFns) {
      auto FnName = F->getName();
      auto FnGUID = uniqueGUID(M.getSourceFileName(), F);
      if (LLVM_UNLIKELY(AutoJITDebug)) {
        errs() << "autojit-plugin: Lazify function " << FnName << " as "
               << guidToFnName(FnGUID) << "\n";
      }
      if (canUseLeanTrampoline(*F)) {
        if (!ResolverThunk)
          ResolverThunk = emitResolverThunk(M);
        lazifyFnLean(F, FnGUID, ResolverThunk, LazyModule);
      } else {
        if (!MaterializeFn) {
          FunctionType *MaterializeFnTy = FunctionType::get(
              PtrTy, {PtrTy, Type::getInt64Ty(Context), PtrTy}, false);
          MaterializeFn = M.getOrInsertFunction("__llvm_autojit_materialize",
                                                MaterializeFnTy);
        }
        lazifyFn(F, FnGUID, MaterializeFn, LazyModule);
      }
    }

    addRuntimeDependency(M);

    // Static code doesn't use them and objects that do have their own copies
    for (Function *F : PrivateFns) {
      F->deleteBody();
      F->setComdat(nullptr);
    }
    for (Function *F : KeptStatic)
      F->removeFnAttr(autojit::KeepStaticAttr);

    // Add all at once: each call rebuilds the entire llvm.used array
    SmallVector<GlobalValue *, 16> Used(LazifyFns.begin(), LazifyFns.end());
    appendToUsed(M, Used);
    appendToCompilerUsed(M, KeepVars);

    if (LLVM_UNLIKELY(AutoJITDebug)) {
      saveModule(M, FileStem + "_static" + FileExt);
    }

    return PreservedAnalyses::none();
  }

private:
  PassBuilder *PB = nullptr;
  OptimizationLevel Level = OptimizationLevel::O0;

  static const SpecialCaseList *getIgnoreList() {
    static const std::unique_ptr<SpecialCaseList> List = [] {
      std::unique_ptr<SpecialCaseList> L;
      if (!AutoJITIgnoreList.empty())
        L = SpecialCaseList::createOrDie({AutoJITIgnoreList},
                                         *vfs::getRealFileSystem());
      return L;
    }();
    return List.get();
  }

  // Mark what must stay in static code. The runtime learns from the mark in the
  // lazy module.
  SmallVector<Function *, 8>
  markStaticFunctions(Module &M, ModuleAnalysisManager &MAM,
                      const SpecialCaseList *IgnoreList) {
    FunctionAnalysisManager &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    SmallVector<Function *, 8> Marked;
    auto Mark = [&](Function &F, const char *Reason) {
      if (F.hasFnAttribute(autojit::KeepStaticAttr))
        return false;
      if (LLVM_UNLIKELY(AutoJITDebug))
        errs() << "autojit-plugin: Keep " << F.getName()
               << " in static code: " << Reason << "\n";
      F.addFnAttr(autojit::KeepStaticAttr);
      Marked.push_back(&F);
      return true;
    };

    // The dynamic linker calls ifunc resolvers while it relocates the program
    for (GlobalIFunc &GI : M.ifuncs())
      if (Function *Resolver = GI.getResolverFunction())
        if (!Resolver->isDeclaration())
          Mark(*Resolver, "ifunc resolver");

    SmallVector<Function *, 8> LibFuncs;
    for (Function &F : M) {
      if (F.isDeclaration() || F.hasAvailableExternallyLinkage() ||
          autojit::isStaticInit(F))
        continue;
      if (hasAddressTakenLabel(F) || hasInlineAsm(F))
        Mark(F, "the code depends on its location");
      if (IgnoreList && IgnoreList->inSection("", "fun", F.getName()))
        Mark(F, "in the ignore list");
      if (AutoJITStaticLibFuncs && !F.hasLocalLinkage() && isLibFunc(F, FAM)) {
        Mark(F, "library function");
        LibFuncs.push_back(&F);
      }
    }

    // The C library and our runtime call library functions while we materialize.
    // Anything they call in this module must not be lazy, e.g. in allocators.
    while (!LibFuncs.empty()) {
      Function *F = LibFuncs.pop_back_val();
      for (BasicBlock &BB : *F)
        for (Instruction &I : BB)
          for (Value *Op : I.operands())
            if (auto *Callee = dyn_cast<Function>(Op->stripPointerCasts()))
              if (!Callee->isDeclaration() && !Callee->isIntrinsic() &&
                  !Callee->hasAvailableExternallyLinkage() &&
                  Mark(*Callee, "called from a library function"))
                LibFuncs.push_back(Callee);
    }
    // Linkonce functions with only calls don't get trampolines anyway. They are
    // private to the JIT and get inlined there.
    if (AutoJITStaticThreshold != 0) {
      for (Function &F : M) {
        F.removeDeadConstantUsers();
        if (!isSmallLeaf(F) ||
            (F.hasLinkOnceODRLinkage() && !autojit::hasNonCallUses(F)))
          continue;
        // The JIT can inline it, if the definition can't be interposed
        bool Exact = F.hasLinkOnceODRLinkage() || F.hasWeakODRLinkage() ||
                     F.isDSOLocal();
        if (Mark(F, "small leaf function") && Exact)
          F.addFnAttr(autojit::KeepStaticAttr, autojit::KeepStaticWithBody);
      }
    }
    return Marked;
  }

  static bool isSmallLeaf(const Function &F) {
    if (F.isDeclaration() || F.hasAvailableExternallyLinkage() ||
        autojit::isStaticInit(F) || F.isVarArg() || F.hasPersonalityFn() ||
        F.hasFnAttribute(Attribute::Naked))
      return false;
    unsigned Count = 0;
    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (CB && !isa<IntrinsicInst>(CB))
          return false;
        if (++Count > AutoJITStaticThreshold)
          return false;
      }
    }
    return true;
  }

  // One line per module, for scripts that sum up the share of lazy functions
  void writeStats(const Module &M, const autojit::LazyBindings &Bindings) {
    if (AutoJITStats.empty())
      return;
    unsigned Counts[5] = {0, 0, 0, 0, 0};
    for (const Function &F : M)
      if (!F.isDeclaration() && !F.hasAvailableExternallyLinkage())
        Counts[static_cast<unsigned>(Bindings.get(F))] += 1;
    std::error_code EC;
    raw_fd_ostream OS(AutoJITStats, EC, sys::fs::OF_Append);
    if (EC)
      return;
    OS << "static=" << Counts[0] << " local=" << Counts[1]
       << " private=" << Counts[2] << " direct=" << Counts[3]
       << " proxy=" << Counts[4] << " " << M.getSourceFileName() << "\n";
  }

  static bool hasAddressTakenLabel(const Function &F) {
    for (const BasicBlock &BB : F)
      if (BB.hasAddressTaken())
        return true;
    return false;
  }

  // The backend must see inline asm at compile-time: the asm text might name
  // symbols, which bypasses our import table, and it's invalid for other targets.
  // configure scripts rely on the resulting error, e.g. CPython checks for x87.
  static bool hasInlineAsm(const Function &F) {
    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (CB && CB->isInlineAsm() &&
            !cast<InlineAsm>(CB->getCalledOperand())->getAsmString().empty())
          return true;
      }
    }
    return false;
  }

  // We run at pipeline start. The runtime runs everything that follows on the
  // lazy module. Clang registered its own passes with the PassBuilder already,
  // so they are part of this. We always record the regular per-module pipeline:
  // the LTO prelink pipelines rely on a postlink stage that never happens here.
  void recordPipeline(Module &M) {
    if (AutoJITPipeline.empty() && !PB)
      return;
    std::string Pipeline = AutoJITPipeline;
    if (Pipeline.empty()) {
      RecordingPipeline = true;
      ModulePassManager MPM = Level == OptimizationLevel::O0
                                  ? PB->buildO0DefaultPipeline(Level)
                                  : PB->buildPerModuleDefaultPipeline(Level);
      RecordingPipeline = false;
      PassInstrumentationCallbacks *PIC = PB->getPassInstrumentationCallbacks();
      raw_string_ostream OS(Pipeline);
      MPM.printPipeline(OS, [PIC](StringRef ClassName) {
        StringRef Name =
            PIC ? PIC->getPassNameForClassName(ClassName) : StringRef();
        return Name.empty() ? ClassName : Name;
      });
    }
    LLVMContext &Ctx = M.getContext();
#if AUTOJIT_LLVM_21
    unsigned CodeGenLevel = Level.getSpeedupLevel();
#else
    unsigned CodeGenLevel = static_cast<unsigned>(Level);
#endif
    M.getOrInsertNamedMetadata(autojit::PipelineMetadata)
        ->addOperand(MDNode::get(
            Ctx, {MDString::get(Ctx, Pipeline),
                  MDString::get(Ctx, Twine(CodeGenLevel).str())}));
  }

  // The executable exports its definitions of library functions, because the
  // C library defines them as well. They interpose the ones in the C library,
  // so the C library and our runtime call them. Symbols interpose by name, so
  // we don't check the prototype.
  static bool isLibFunc(Function &F, FunctionAnalysisManager &FAM) {
    const TargetLibraryInfo &TLI = FAM.getResult<TargetLibraryAnalysis>(F);
#if AUTOJIT_LLVM_21 || AUTOJIT_LLVM_23
    LibFunc Func;
    return TLI.getLibFunc(F.getName(), Func);
#else
    return TLI.getLibFunc(F.getName()) != NotLibFunc;
#endif
  }

  // The runtime loads lazy modules from their absolute path and caches their
  // compiled objects next to them.
  static const std::string &getOutputDir() {
    static const std::string Dir = [] {
      SmallString<256> Path(AutoJITDir);
      if (std::error_code EC = sys::fs::make_absolute(Path)) {
        errs() << "autojit-plugin error: Invalid directory " << AutoJITDir
               << ": " << EC.message() << "\n";
        exit(1);
      }
      if (std::error_code EC = sys::fs::create_directories(Path)) {
        errs() << "autojit-plugin error: Failed to create directory " << Path
               << ": " << EC.message() << "\n";
        exit(1);
      }
      return std::string(Path);
    }();
    return Dir;
  }

  // One source file can be compiled in many ways into one directory, e.g. for a
  // static and a shared library, so the name depends on the compile options.
  // Options are ordered, because later ones can override earlier ones. Reading
  // them from the process needs no extra flag: without integrated cc1, these are
  // the options of the cc1 process, which tell compiles apart just as well.
  std::string getModuleGUID(const Module &M) {
    // Get the original source file path from the module
    SmallString<256> SourcePath(M.getSourceFileName());
    if (SourcePath.empty()) {
      errs() << "autojit-plugin error: Invalid source path in module: "
             << SourcePath << "\n";
      exit(1);
    }
    // Relative paths are the same across projects
    sys::fs::make_absolute(SourcePath);

    MD5 Hasher;
    Hasher.update(SourcePath);
    Hasher.update(ArrayRef<uint8_t>{0});
    std::ifstream CmdLine("/proc/self/cmdline", std::ios::binary);
    std::string Arg;
    bool First = true;
    bool SkipNext = false;
    while (std::getline(CmdLine, Arg, '\0')) {
      if (std::exchange(First, false) || std::exchange(SkipNext, false))
        continue;
      // Paths of outputs don't affect the code
      if (Arg == "-o" || Arg == "-MF" || Arg == "-MT" || Arg == "-MQ") {
        SkipNext = true;
        continue;
      }
      if (Arg == "-MD" || Arg == "-MMD")
        continue;
      Hasher.update(Arg);
      Hasher.update(ArrayRef<uint8_t>{0});
    }

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

  // Emit the descriptor that trampolines pass to the runtime. See
  // common/LazyModule.h for the layout.
  static GlobalVariable *emitLazyModule(Module &M,
                                        ArrayRef<GlobalValue *> Imports,
                                        uint64_t Hash, StringRef FilePath) {
    LLVMContext &Ctx = M.getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    PointerType *PtrTy = PointerType::get(Ctx, 0);
    // Header, import entries, bitmap of indirect entries and the path inline,
    // so the descriptor has no relocations that the loader would process
    unsigned NumEntries = Imports.size();
    ArrayType *EntriesTy = ArrayType::get(I32Ty, NumEntries);
    ArrayType *IndirectTy =
        ArrayType::get(Type::getInt8Ty(Ctx), (NumEntries + 7) / 8);
    Constant *Path = ConstantDataArray::getString(Ctx, FilePath);
    StructType *TableTy = StructType::get(
        Ctx, {I32Ty, I32Ty, I64Ty, EntriesTy, IndirectTy, Path->getType()});

    // Entries refer to their own address, so create the global first
    auto *Table = new GlobalVariable(M, TableTy, true,
                                     GlobalValue::PrivateLinkage, nullptr,
                                     "__llvm_autojit_module");
    Table->setAlignment(Align(8));

    SmallVector<Constant *, 32> Entries;
    Entries.reserve(NumEntries);
    SmallVector<uint8_t, 8> Indirect((NumEntries + 7) / 8, 0);
    // Module flags are expensive to look up, so we do it once
    const Triple &TT = M.getTargetTriple();
    std::optional<CodeModel::Model> CM = M.getCodeModel();
    uint64_t LargeDataThreshold = M.getLargeDataThreshold().value_or(0);
    bool IsSharedLibCode =
        M.getPICLevel() != PICLevel::NotPIC && M.getPIELevel() == PIELevel::Default;

#if AUTOJIT_LLVM_21
    Constant *Zero = ConstantInt::get(I32Ty, 0);
    Constant *EntriesIdx = ConstantInt::get(I32Ty, 3);
#else
    uint64_t EntriesOffset =
        M.getDataLayout().getStructLayout(TableTy)->getElementOffset(3);
#endif
    for (unsigned I = 0; I < NumEntries; I += 1) {
      GlobalValue *GV = Imports[I];
      Constant *Target = GV;
      // Symbols that might be outside the linked image or out of range for a
      // 32-bit offset go through a GOT-equivalent slot. The backend folds it
      // into a reference to the symbol's GOT entry, which regular code shares.
      // In shared libraries, the linker considers symbols with default
      // visibility preemptible, even if -fno-semantic-interposition made them
      // dso_local.
      if (!GV->isDSOLocal() || GV->hasExternalWeakLinkage() ||
          isa<GlobalIFunc>(GV) ||
          (IsSharedLibCode && !GV->hasLocalLinkage() &&
           GV->hasDefaultVisibility()) ||
          mayBeOutOfRange(*GV, TT, CM, LargeDataThreshold)) {
        auto *Slot = new GlobalVariable(M, PtrTy, true,
                                        GlobalValue::PrivateLinkage, GV,
                                        "__llvm_autojit_got");
        // On AArch64, the backend would fold it into R_AARCH64_GOTPCREL32,
        // which GNU ld doesn't support (as of 2.42). Without unnamed_addr,
        // the slot stays in .data.rel.ro and the loader fills it.
        if (!TT.isAArch64())
          Slot->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        Target = Slot;
        Indirect[I / 8] |= 1 << (I % 8);
      }
      // Offset from the entry to its target: a static relocation that the
      // linker resolves, since both are in the same image
#if AUTOJIT_LLVM_21
      Constant *Idx[] = {Zero, EntriesIdx, ConstantInt::get(I32Ty, I)};
      Constant *Place =
          ConstantExpr::getInBoundsGetElementPtr(TableTy, Table, Idx);
#else
      Constant *Place = ConstantExpr::getInBoundsPtrAdd(
          Table, ConstantInt::get(I64Ty, EntriesOffset + I * 4));
#endif
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

  // Lean trampolines only jump through their slot and leave all arguments
  // untouched. They need scratch registers that the C calling convention
  // doesn't use for arguments: r11 on x86-64, x16 and x17 on AArch64. They
  // address the slot PC-relative, which might be out of range with the large
  // code model.
  static bool canUseLeanTrampoline(const Function &F) {
    const Module &M = *F.getParent();
    const Triple &TT = M.getTargetTriple();
    if (!TT.isOSBinFormatELF() || M.getCodeModel() == CodeModel::Large ||
        F.getCallingConv() != CallingConv::C)
      return false;
    switch (TT.getArch()) {
    case Triple::x86_64:
      return true;
    case Triple::aarch64:
      // GlobalISel spills vararg registers even in naked functions, which
      // writes into the caller's frame (LLVM 21) or asserts (LLVM 24)
      return TT.getEnvironment() != Triple::GNUILP32 && !hasSMEAttrs(F) &&
             !F.isVarArg();
    default:
      return false;
    }
  }

  // The resolver is a regular function that we enter in non-streaming mode
  // without ZA state. Functions with SME attributes keep the generic
  // trampoline, which the backend handles as a regular call.
  static bool hasSMEAttrs(const Function &F) {
    for (const Attribute &A : F.getAttributes().getFnAttrs())
      if (A.isStringAttribute() && A.getKindAsString().starts_with("aarch64_"))
        return true;
    return false;
  }

  static Function *createNakedFunction(Function *F) {
    F->addFnAttr(Attribute::Naked);
    F->addFnAttr(Attribute::NoUnwind);
    // The jump is only valid in the trampoline itself. At -O0, the always
    // inliner still runs after us (e.g. for allocators in libstdc++ 13).
    F->removeFnAttr(Attribute::AlwaysInline);
    F->addFnAttr(Attribute::NoInline);
    // No unwind info: trampolines don't have a frame
    F->removeFnAttr(Attribute::UWTable);
    return F;
  }

  // lld adds it once per object, so the default is an archive and not the
  // stub's linker script. Its only member gets pulled once and only if nothing
  // else on the link line defines our entry points.
  static std::string getRuntimePath() {
    if (!AutoJITRuntime.empty())
      return AutoJITRuntime;
    Dl_info Info;
    if (!dladdr(reinterpret_cast<void *>(&getRuntimePath), &Info) ||
        !Info.dli_fname)
      return "";
    SmallString<256> Path(Info.dli_fname);
    sys::path::remove_filename(Path);
    sys::path::append(Path, "libautojit_static.a");
    sys::fs::make_absolute(Path);
    return std::string(Path);
  }

  // Put the runtime on the link line of linkers that support .deplibs, i.e.
  // lld. Other linkers ignore it and need the compiler wrappers or explicit
  // flags. Only absolute paths work without further linker flags.
  static void addRuntimeDependency(Module &M) {
    if (AutoJITNoDeplibs)
      return;
    std::string Path = getRuntimePath();
    if (!sys::path::is_absolute(Path))
      return;
    LLVMContext &Ctx = M.getContext();
    M.getOrInsertNamedMetadata("llvm.dependent-libraries")
        ->addOperand(MDNode::get(Ctx, MDString::get(Ctx, Path)));
  }

  // Slots of lean trampolines initially point to this thunk. It's local to
  // the module, so the slots get relative relocations. The resolver is in the
  // runtime (see runtime/common/Resolver*.c). On x86-64, the backend emits
  // endbr64 for CET based on the module flag. On AArch64, it emits BTI only
  // for functions with the attribute, which clang adds to all functions.
  static Function *emitResolverThunk(Module &M) {
    LLVMContext &Context = M.getContext();
    FunctionType *FnTy = FunctionType::get(Type::getVoidTy(Context), false);
    Function *Thunk = createNakedFunction(Function::Create(
        FnTy, GlobalValue::InternalLinkage, "__llvm_autojit_resolve_thunk", M));
    FunctionCallee Resolver =
        M.getOrInsertFunction("__llvm_autojit_resolve", FnTy);
    StringRef AsmStr;
    if (M.getTargetTriple().getArch() == Triple::aarch64) {
      // x16 holds the entry, so we can only use x17
      AsmStr = "adrp x17, :got:${0:c}\n"
               "ldr x17, [x17, :got_lo12:${0:c}]\n"
               "br x17";
      auto *BTI = mdconst::extract_or_null<ConstantInt>(
          M.getModuleFlag("branch-target-enforcement"));
      if (BTI && !BTI->isZero())
        Thunk->addFnAttr("branch-target-enforcement");
    } else {
      AsmStr = "jmpq *${0:P}@GOTPCREL(%rip)";
    }
    IRBuilder<> Builder(BasicBlock::Create(Context, "entry", Thunk));
    PointerType *PtrTy = PointerType::get(Context, 0);
    InlineAsm *Asm = InlineAsm::get(
        FunctionType::get(Type::getVoidTy(Context), {PtrTy}, false), AsmStr,
        "s", /*hasSideEffects=*/true);
    Builder.CreateCall(Asm, {Resolver.getCallee()});
    Builder.CreateUnreachable();
    return Thunk;
  }

  // The trampoline passes its entry in a scratch register and jumps through
  // the slot. The entry follows the jump, see autojit_trampoline_entry_t.
  // Slots of linkonce functions go into their comdat, so the linker discards
  // them together.
  void lazifyFnLean(Function *F, GlobalValue::GUID FnGUID,
                    Function *ResolverThunk, GlobalVariable *LazyModule) {
    Module *M = F->getParent();
    LLVMContext &Context = M->getContext();
    PointerType *PtrTy = PointerType::get(Context, 0);

    auto *Slot = new GlobalVariable(*M, PtrTy, false,
                                    GlobalValue::InternalLinkage, ResolverThunk,
                                    "__llvm_autojit_ptr_" + F->getName());
    Slot->setAlignment(Align(8));
    Slot->setComdat(F->getComdat());

    F->dropAllReferences();
    createNakedFunction(F);
    IRBuilder<> Builder(BasicBlock::Create(Context, "entry", F));
    std::string AsmStr;
    raw_string_ostream OS(AsmStr);
    if (M->getTargetTriple().getArch() == Triple::aarch64) {
      // x16 and x17 are the intra-procedure-call scratch registers. With BTI,
      // br x17 may land on "bti c" in the resolver thunk. The runtime stores
      // the slot with release semantics after it linked the code. We load it
      // with acquire semantics, so the JITed code sees its data.
      OS << "adr x16, 1f\n"
         << "adrp x17, ${0:c}\n"
         << "add x17, x17, :lo12:${0:c}\n"
         << "ldar x17, [x17]\n"
         << "br x17\n"
         << "1:\n"
         << ".xword " << FnGUID << "\n"
         << ".word ${0:c} - 1b\n"
         << ".word ${1:c} - 1b";
    } else {
      OS << "leaq 1f(%rip), %r11\n"
         << "jmpq *${0:P}(%rip)\n"
         << "1:\n"
         << ".quad " << FnGUID << "\n"
         << ".long ${0:P} - 1b\n"
         << ".long ${1:P} - 1b";
    }
    FunctionType *AsmTy = FunctionType::get(Type::getVoidTy(Context),
                                            {PtrTy, PtrTy}, false);
    InlineAsm *Asm = InlineAsm::get(AsmTy, AsmStr, "s,s",
                                    /*hasSideEffects=*/true);
    Builder.CreateCall(Asm, {Slot, LazyModule});
    Builder.CreateUnreachable();
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

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  if (const char *Var = std::getenv("AUTOJIT_DEBUG")) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      AutoJITDebug = true;
  }
  if (const char *Var = std::getenv("AUTOJIT_STATIC_LIBFUNCS")) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "0" || Val == "off" || Val == "false" || Val == "no")
      AutoJITStaticLibFuncs = false;
  }
  if (const char *Var = std::getenv("AUTOJIT_DIR"))
    if (*Var)
      AutoJITDir = Var;
  if (const char *Var = std::getenv("AUTOJIT_STATIC_THRESHOLD")) {
    unsigned Threshold;
    if (!StringRef(Var).getAsInteger(10, Threshold))
      AutoJITStaticThreshold = Threshold;
  }
  if (const char *Var = std::getenv("AUTOJIT_IGNORELIST"))
    if (*Var)
      AutoJITIgnoreList = Var;
  if (const char *Var = std::getenv("AUTOJIT_STATS"))
    if (*Var)
      AutoJITStats = Var;
  if (const char *Var = std::getenv("AUTOJIT_RUNTIME"))
    if (*Var)
      AutoJITRuntime = Var;
  if (const char *Var = std::getenv("AUTOJIT_NO_DEPLIBS")) {
    StringRef Val(Var);
    AutoJITNoDeplibs = !Val.empty() && !Val.equals_insensitive("0") &&
                       !Val.equals_insensitive("off") &&
                       !Val.equals_insensitive("false") &&
                       !Val.equals_insensitive("no");
  }
  return {.APIVersion = LLVM_PLUGIN_API_VERSION,
          .PluginName = "AutoJIT Pass",
          .PluginVersion = "v0.1",
          .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
            // Register to run automatically at the start of the module
            // pipeline. PB outlives the pipeline that it builds.
            PB.registerPipelineStartEPCallback(
                [&PB](ModulePassManager &MPM, OptimizationLevel Level) {
                  if (RecordingPipeline)
                    return;
                  MPM.addPass(AutoJITPass(PB, Level));
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
