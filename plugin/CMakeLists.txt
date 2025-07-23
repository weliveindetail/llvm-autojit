# Build the AutoJIT pass plugin
add_llvm_pass_plugin(autojit
  SUBPROJECT llvm-autojit
    AutoJITPass.cpp

  LINK_COMPONENTS
    Core
    Passes
    Support
  )

# Don't add a 'lib' prefix to the plugin
set_target_properties(autojit PROPERTIES PREFIX "")
