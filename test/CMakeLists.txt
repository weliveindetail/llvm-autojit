# Configure lit site configuration
llvm_canonicalize_cmake_booleans(
  LLVM_ENABLE_PLUGINS
  BUILD_SHARED_LIBS
)

set(LLVM_LIT_ARGS "-vv --no-progress-bar")

if(AUTOJIT_BUILD_EXTERNAL)
  find_program(clang_exec
               NAMES clang-20 clang
               HINTS ${LLVM_TOOLS_BINARY_DIR})
  if(clang_exec)
    message(STATUS "Found: ${clang_exec}")
    add_executable(clang IMPORTED GLOBAL)
    set_target_properties(clang PROPERTIES IMPORTED_LOCATION clang_exec)
  else()
    message(WARNING "clang not found")
  endif()

  find_program(LLVM_EXTERNAL_LIT lit)
  if(LLVM_EXTERNAL_LIT)
    message(STATUS "Found: ${LLVM_EXTERNAL_LIT}")
  else()
    message(WARNING "lit not found")
  endif()
endif()

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
)

set(AUTOJIT_TEST_DEPENDS
  autojit
  autojit-runtime
  llvm-ar
  llvm-config
  clang
  opt
  FileCheck
  count
  not
)

# Add the test suite
add_lit_testsuite(check-autojit "Running the AutoJIT tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${AUTOJIT_TEST_DEPENDS}
)

# Set folder properties for IDE organization
set_target_properties(check-autojit PROPERTIES FOLDER "AutoJIT/Tests")
