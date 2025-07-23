# Build the AutoJIT runtime library
if(AUTOJIT_ENABLE_TPDE)
  # TODO: Add define AUTOJIT_ENABLE_TPDE in C++
  set(tpde_libs tpde tpde_llvm)
endif()

add_llvm_library(autojit-runtime SHARED
  AutoJITRuntime.cpp

  LINK_COMPONENTS
    BitcodeReader
    Core
    ExecutionEngine
    MCJIT
    Native
    Support
    Target

  LINK_LIBS
    ${tpde_libs}
  )
