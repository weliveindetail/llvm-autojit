
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

option(AUTOJIT_ENABLE_TPDE "Build the autojit-runtime with TPDE as codegen backend" OFF)
option(AUTOJIT_ENABLE_ORC_RUNTIME "Enable orc-runtime support in the autojit-runtime" OFF)

set(AUTOJIT_CONFIG_FILE_DIR ${CMAKE_CURRENT_BINARY_DIR})
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/AutoJITConfig.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/AutoJITConfig.h
)

if(DEFINED LLVM_MAIN_SRC_DIR)
  set(AUTOJIT_BUILD_EXTERNAL Off)
  set(AUTOJIT_BUILD_UNIFIED On)
else()
  set(AUTOJIT_BUILD_EXTERNAL On)
  set(AUTOJIT_BUILD_UNIFIED Off)

  cmake_minimum_required(VERSION 3.20.0)
  project(llvm-autojit)
  set(AUTOJIT_STANDALONE_BUILD True)

  find_package(LLVM REQUIRED CONFIG)
  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

  include_directories(${LLVM_INCLUDE_DIRS})
  separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
  add_definitions(${LLVM_DEFINITIONS_LIST})

  set(LLVM_NO_RTTI 1)
endif()

if(AUTOJIT_ENABLE_TPDE)
  add_compile_options(-Wno-unused-parameter)
  set(TPDE_LINK_LLVM_STATIC On)
  add_subdirectory(deps/tpde)
endif()

# Add subdirectories for plugin and runtime
add_subdirectory(plugin)
add_subdirectory(runtime)

# Create a master install target that depends on the LLVM-generated install targets
# add_llvm_pass_plugin creates an install-autojit target automatically

# If install-autojit doesn't exist (meaning the plugin didn't create it), create it
if(NOT TARGET install-autojit)
  add_custom_target(install-autojit
    COMMENT "Installing all AutoJIT components"
  )
endif()

# Add header installation
install(FILES runtime/AutoJITRuntime.h
  DESTINATION include
  RENAME llvm-autojit.h
  COMPONENT autojit-headers
)

# Create a custom target for header installation
add_custom_target(install-autojit-headers
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-headers
  COMMENT "Installing AutoJIT headers"
)

# FIXME: We need a separate install-autojit-plugin target
add_dependencies(install-autojit install-autojit-runtime install-autojit-headers)

add_subdirectory(benchmark)
add_subdirectory(test)
