# Build the AutoJIT runtime library
if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
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

# Root directory has the generated config header
target_include_directories(autojit-runtime PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
