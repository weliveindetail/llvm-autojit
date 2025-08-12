#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Target/X86/X86TargetMachine.h"
#include "llvm/TargetParser/Triple.h"

class TPDEPass : public llvm::ModulePass {
public:
  static char ID;

  TPDEPass(llvm::raw_pwrite_stream &Out) : llvm::ModulePass(ID), OS(Out) {}
  bool runOnModule(llvm::Module &M) override;

  llvm::StringRef getPassName() const override {
    return "Single-pass TPDE backend";
  }

private:
  llvm::raw_pwrite_stream &OS;
};

class X86TargetMachineTPDE : public llvm::X86TargetMachine {
public:
  X86TargetMachineTPDE(const llvm::Target &T, const llvm::Triple &TT, llvm::StringRef CPU,
                       llvm::StringRef FS, const llvm::TargetOptions &Options,
                       std::optional<llvm::Reloc::Model> RM,
                       std::optional<llvm::CodeModel::Model> CM, llvm::CodeGenOptLevel OL,
                       bool JIT)
      : X86TargetMachine(T, TT, CPU, FS, Options, RM, CM, OL, JIT) {}

  bool
  addPassesToEmitFile(llvm::PassManagerBase &PM, llvm::raw_pwrite_stream &Out,
                      llvm::raw_pwrite_stream *DwoOut, llvm::CodeGenFileType FileType,
                      bool DisableVerify = true,
                      llvm::MachineModuleInfoWrapperPass *MMIWP = nullptr) override {
    PM.add(new TPDEPass(Out));
    return false; // success
  }
};
