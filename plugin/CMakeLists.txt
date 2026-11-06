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

# Compiler wrappers: the fallback for linkers that ignore .deplibs
configure_file(autojit-clang.in ${CMAKE_BINARY_DIR}/bin/autojit-clang @ONLY
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                   GROUP_READ GROUP_EXECUTE
                   WORLD_READ WORLD_EXECUTE
)
file(CREATE_LINK autojit-clang ${CMAKE_BINARY_DIR}/bin/autojit-clang++ SYMBOLIC)
install(
  PROGRAMS ${CMAKE_BINARY_DIR}/bin/autojit-clang ${CMAKE_BINARY_DIR}/bin/autojit-clang++
  DESTINATION bin
  COMPONENT autojit-wrappers
)
add_custom_target(install-autojit-wrappers
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-wrappers
  COMMENT "Installing AutoJIT compiler wrappers"
)
