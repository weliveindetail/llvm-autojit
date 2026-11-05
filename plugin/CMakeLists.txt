if(AUTOJIT_BUILD_EXTERNAL)
  include(${LLVM_BINARY_DIR}/lib/cmake/llvm/AddLLVM.cmake)
endif()

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
# PCH doesn't fit since the plugin builds with C++20
set_target_properties(autojit PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  DISABLE_PRECOMPILE_HEADERS On
  PREFIX ""
)
