# Configure lit site configuration
llvm_canonicalize_cmake_booleans(
  LLVM_ENABLE_PLUGINS
  BUILD_SHARED_LIBS
)

set(LLVM_LIT_ARGS "-vv --no-progress-bar")

if(AUTOJIT_BUILD_EXTERNAL)
  find_program(CLANG NO_CACHE REQUIRED
               NAMES clang-20 clang
               HINTS ${LLVM_TOOLS_BINARY_DIR})
  if(CLANG)
    message(STATUS "Found Clang: " ${CLANG})
  else()
    set(CLANG /usr/lib/llvm-20/bin/clang)
  endif()

  add_executable(clang IMPORTED GLOBAL)
  set_target_properties(clang PROPERTIES
    IMPORTED_LOCATION "${CLANG}"
  )
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
