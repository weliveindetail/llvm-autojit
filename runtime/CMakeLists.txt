# Build the AutoJIT runtime library
if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
endif()

# TODO: bundle lib/clang/20/lib/x86_64-unknown-linux-gnu/liborc_rt.a
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
target_link_options(autojit-runtime PRIVATE -Wl,-Bsymbolic)
