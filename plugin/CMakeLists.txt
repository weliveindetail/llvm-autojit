# Build the AutoJIT runtime library
# TPDEBackends.cpp subclasses the X86TargetMachine, which is a private and
# final class in vanilla LLVM. Only the runtime uses TPDE for now.
set(tpde_backends PARTIAL_SOURCES_INTENDED)

if(AUTOJIT_BUILD_EXTERNAL)
  include(${LLVM_BINARY_DIR}/lib/cmake/llvm/AddLLVM.cmake)
endif()

# Build the AutoJIT pass plugin
add_llvm_pass_plugin(autojit
  SUBPROJECT llvm-autojit
    AutoJITPass.cpp
    ${tpde_backends}

  LINK_COMPONENTS
    Core
    Passes
    Support

  LINK_LIBS
    ${tpde_libs}
  )

# Don't add a 'lib' prefix to the plugin
set_target_properties(autojit PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  PREFIX ""
)
