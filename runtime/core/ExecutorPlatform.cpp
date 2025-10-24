#include "runtime/core/ExecutorPlatform.h"

#include "llvm/ExecutionEngine/Orc/DebugObjectManagerPlugin.h"
#include "llvm/ExecutionEngine/Orc/ELFNixPlatform.h"
#include "llvm/ExecutionEngine/Orc/EPCDebugObjectRegistrar.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/ObjectLinkingLayer.h"
#include "llvm/ExecutionEngine/Orc/TargetProcess/JITLoaderGDB.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

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

// Linker fills in relocations for the bounds of the linked liborc_rt.a, which
// resolve to the actual memory load addresses at startup.
extern "C" const unsigned char _binary_liborc_rt_start[];
extern "C" const unsigned char _binary_liborc_rt_end[];

static bool isEnvVarSet(const char *Name) {
  if (const char *Var = std::getenv(Name)) {
    std::string Val{Var};
    std::transform(Val.begin(), Val.end(), Val.begin(), ::tolower);
    if (Val == "1" || Val == "on" || Val == "true" || Val == "yes")
      return true;
  }
  return false;
}

static Error installDebugSupport(ObjectLinkingLayer *JITLinkLayer) {
  auto &ES = JITLinkLayer->getExecutionSession();
  auto StubDebug = createJITLoaderGDBRegistrar(ES);
  if (!StubDebug)
    return StubDebug.takeError();

  bool AutoRegisterCode = true;
  if (isEnvVarSet("AUTOJIT_DEBUG_NO_AUTOREGISTER")) {
    // Call __jit_debug_register_code() before debugging into JITed code
    AutoRegisterCode = false;
  }
  constexpr bool RequireDebugSections = false;
  auto Plugin = std::make_unique<DebugObjectManagerPlugin>(
      ES, std::move(*StubDebug), RequireDebugSections, AutoRegisterCode);
  JITLinkLayer->addPlugin(std::move(Plugin));
  return Error::success();
}

static std::unique_ptr<MemoryBuffer> getEmbeddedOrcRuntime() {
#if defined(AUTOJIT_ENABLE_ORC_RUNTIME)
  const char *OrcRtStart =
      reinterpret_cast<const char *>(_binary_liborc_rt_start);
  const char *OrcRtEnd = reinterpret_cast<const char *>(_binary_liborc_rt_end);
  StringRef OrcRuntimeData(OrcRtStart, OrcRtEnd - OrcRtStart);
#if !defined(NDEBUG)
  auto MemRngStr = format("[0x%" PRIx64 ", 0x%" PRIx64 "]",
                          reinterpret_cast<uintptr_t>(OrcRtStart),
                          reinterpret_cast<uintptr_t>(OrcRtEnd));
  DBG() << "Install embedded orc-runtime from memory range " << MemRngStr
        << "\n";
#endif
  return MemoryBuffer::getMemBuffer(OrcRuntimeData, "orc_rt", false);
#else
  return nullptr;
#endif // AUTOJIT_ENABLE_ORC_RUNTIME
}

Expected<JITDylibSP> autojit::ExecutorPlatform::operator()(LLJIT &J) {
  auto ProcessSymbolsJD = J.getProcessSymbolsJITDylib();
  assert(ProcessSymbolsJD && "Native platforms require process symbols");

  const Triple &TT = J.getTargetTriple();
  assert(TT.getObjectFormat() == Triple::ELF && "Support other platforms");

  ObjectLinkingLayer *JITLinkLayer =
      dyn_cast<ObjectLinkingLayer>(&J.getObjLinkingLayer());
  assert(JITLinkLayer && "DebuggableExecutorNativePlatform requires JITLink");

  if (isEnvVarSet("AUTOJITD_DISABLE_ORC_RUNTIME")) {
    LOG() << "Skip install orc-runtime: AUTOJITD_DISABLE_ORC_RUNTIME\n";
    return setUpGenericLLVMIRPlatform(J);
  }

  std::unique_ptr<MemoryBuffer> Archive = getEmbeddedOrcRuntime();
  if (!Archive) {
    LOG() << "Cannot install orc-runtime: no embedded liborc_rt\n";
    return setUpGenericLLVMIRPlatform(J);
  }

  if (!HaveOrcRuntimeDeps) {
    LOG() << "Cannot install orc-runtime: missing C++ stdlib\n";
    return setUpGenericLLVMIRPlatform(J);
  }

  auto OrcRuntime = StaticLibraryDefinitionGenerator::Create(
      *JITLinkLayer, std::move(Archive));
  if (!OrcRuntime) {
    LOG() << "Cannot install orc-runtime: " << toString(OrcRuntime.takeError())
          << "\n";
    return setUpGenericLLVMIRPlatform(J);
  }

  auto &ES = J.getExecutionSession();
  auto &PlatformJD = ES.createBareJITDylib("<Platform>");
  PlatformJD.addToLinkOrder(*ProcessSymbolsJD);

  // Setting up debug support first, allows us to debug the runtime code
  if (EnableDebugging) {
    if (Error Err = installDebugSupport(JITLinkLayer))
      LOG() << "Cannot enable debugger support: " << toString(std::move(Err));
  }

  if (auto P = ELFNixPlatform::Create(*JITLinkLayer, PlatformJD,
                                      std::move(*OrcRuntime))) {
    J.getExecutionSession().setPlatform(std::move(*P));
    J.setPlatformSupport(std::make_unique<ORCPlatformSupport>(J));
  } else {
    // At this point we cannot fall back anymore, becasue LLVM doesn't expose
    // the GenericLLVMIRPlatformSupport class.
    LOG() << "Failed to install orc-runtime: " << toString(P.takeError());
  }

  return &PlatformJD;
}
