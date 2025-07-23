# Build the AutoJIT runtime library
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
  )
