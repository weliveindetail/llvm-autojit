# Build the AutoJIT runtime library
if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
  set(tpde_backends TPDEBackends.cpp)
else()
  set(tpde_backends PARTIAL_SOURCES_INTENDED)
endif()

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

# Root directory has the generated config header
target_include_directories(autojit PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
