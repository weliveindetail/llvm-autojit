#include "runtime/core/ExecutorPlatform.h"
#include "runtime/core/OrcCompat.h"

#if AUTOJIT_LLVM_21
#include <llvm/ExecutionEngine/Orc/DebugObjectManagerPlugin.h>
#include <llvm/ExecutionEngine/Orc/EPCDebugObjectRegistrar.h>
#else
#include <llvm/ExecutionEngine/Orc/Debugging/ELFDebugObjectPlugin.h>
#endif
#include <llvm/ExecutionEngine/Orc/ObjectLinkingLayer.h>
#include <llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Triple.h>

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <string>

using namespace llvm;
using namespace llvm::orc;

extern bool g_autojit_debug;

#if defined(NDEBUG)
#define DBG() for (bool _c = false; _c; _c = false)                            \
                ::llvm::nulls()
#else
#define DBG() for (bool _c = g_autojit_debug; _c; _c = false)                  \
                ::llvm::dbgs() << "[autojit-runtime] "
#endif

#define LOG() ::llvm::errs() << "[autojit-runtime] "

// Only the LLVM 21 debug plugin has an auto-register flag
#if AUTOJIT_LLVM_21
static bool isEnvVarSet(const char *Name) {
  if (const char *Var = std::getenv(Name)) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      return true;
  }
  return false;
}
#endif

static Error installDebugSupport(ObjectLinkingLayer *JITLinkLayer) {
  // The executor provides the registration function as bootstrap symbol. We
  // can't look it up by name: it isn't exported from the program.
  auto &ES = JITLinkLayer->getExecutionSession();
  constexpr bool RequireDebugSections = false;
#if AUTOJIT_LLVM_21
  ExecutorAddr RegisterFn;
  if (auto Err = ES.getExecutorProcessControl().getBootstrapSymbols(
          {{RegisterFn, autojit::GDBRegisterBootstrapName}})) {
    consumeError(std::move(Err));
    return createStringError(inconvertibleErrorCode(),
                             "Executor has no GDB JIT interface. Link "
                             "autojit_static_debug instead of autojit_static.");
  }
  auto StubDebug = std::make_unique<EPCDebugObjectRegistrar>(ES, RegisterFn);

  bool AutoRegisterCode = true;
  if (isEnvVarSet("AUTOJIT_DEBUG_NO_AUTOREGISTER")) {
    // Call __jit_debug_register_code() manually before debugging JITed code
    AutoRegisterCode = false;
  }
  auto Plugin = std::make_unique<DebugObjectManagerPlugin>(
      ES, std::move(StubDebug), RequireDebugSections, AutoRegisterCode);
  JITLinkLayer->addPlugin(std::move(Plugin));
  return Error::success();
#else
  // The registration action has no auto-register flag anymore. The remote stub
  // checks AUTOJIT_DEBUG_NO_AUTOREGISTER itself.
  Error Err = Error::success();
  auto Plugin =
      std::make_unique<ELFDebugObjectPlugin>(ES, RequireDebugSections, Err);
  if (Err) {
    consumeError(std::move(Err));
    return createStringError(inconvertibleErrorCode(),
                             "Executor has no GDB JIT interface. Link "
                             "autojit_static_debug instead of autojit_static.");
  }
  JITLinkLayer->addPlugin(std::move(Plugin));
  return Error::success();
#endif
}

Expected<JITDylibSP> autojit::ExecutorPlatform::operator()(LLJIT &J) {
  const Triple &TT = J.getTargetTriple();
  assert(TT.getObjectFormat() == Triple::ELF && "Support other platforms");

  ObjectLinkingLayer *JITLinkLayer =
      dyn_cast<ObjectLinkingLayer>(&J.getObjLinkingLayer());
  assert(JITLinkLayer && "DebuggableExecutorNativePlatform requires JITLink");

  if (EnableDebugging) {
    if (Error Err = installDebugSupport(JITLinkLayer))
      LOG() << "Cannot enable debugger support: " << toString(std::move(Err))
            << "\n";
  }

  return setUpGenericLLVMIRPlatform(J);
}
