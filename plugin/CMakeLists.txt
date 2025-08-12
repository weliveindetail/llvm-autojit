# Build the AutoJIT runtime library
if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
endif()

# Build the AutoJIT pass plugin
add_llvm_pass_plugin(autojit
  SUBPROJECT llvm-autojit
    AutoJITPass.cpp
    TPDEBackends.cpp

  LINK_COMPONENTS
    Core
    Passes
    Support

  LINK_LIBS
    ${tpde_libs}
  )

# Don't add a 'lib' prefix to the plugin
set_target_properties(autojit PROPERTIES PREFIX "")

# Root directory has the generated config header
target_include_directories(autojit PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
