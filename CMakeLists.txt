
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

# Support IN_LIST operator in if clause
cmake_policy(SET CMP0057 NEW)

option(AUTOJIT_ENABLE_TPDE "Build the autojit-runtime with TPDE as codegen backend" OFF)

# Add any other reasonable sanitizers to the list
set(AUTOJIT_SANITIZE_LIST "address" "address,undefined" "thread")
set(AUTOJIT_SANITIZE "" CACHE STRING "Build static runtime with the specified sanitizer")

if(NOT AUTOJIT_SANITIZE STREQUAL "")
  if(NOT "${AUTOJIT_SANITIZE}" IN_LIST AUTOJIT_SANITIZE_LIST)
    string(REPLACE ";" "', '" AUTOJIT_SANITIZE_CSV "${AUTOJIT_SANITIZE_LIST}")
    message(WARNING "Unrecognized value '${AUTOJIT_SANITIZE}' for AUTOJIT_SANITIZE, "
                    "expected empty or one of: '${AUTOJIT_SANITIZE_CSV}'")
  endif()
endif()

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

set(AUTOJIT_SUPPORTED_LLVM_VERSIONS 21 23 24)
if(NOT LLVM_VERSION_MAJOR IN_LIST AUTOJIT_SUPPORTED_LLVM_VERSIONS)
  string(REPLACE ";" ", " supported "${AUTOJIT_SUPPORTED_LLVM_VERSIONS}")
  message(FATAL_ERROR "LLVM ${LLVM_VERSION_MAJOR} is not supported, "
                      "llvm-autojit supports: ${supported}")
endif()

# Guards legacy code, LLVM 24 is the default
if(LLVM_VERSION_MAJOR EQUAL 21)
  set(AUTOJIT_LLVM_21 On)
else()
  set(AUTOJIT_LLVM_21 Off)
endif()
if(LLVM_VERSION_MAJOR EQUAL 23)
  set(AUTOJIT_LLVM_23 On)
else()
  set(AUTOJIT_LLVM_23 Off)
endif()
if(LLVM_VERSION_MAJOR LESS 24)
  set(AUTOJIT_LLVM_LEGACY On)
else()
  set(AUTOJIT_LLVM_LEGACY Off)
endif()

# JITed code can call compiler builtins that programs don't export. They come from
# compiler-rt of the LLVM that generates the code.
if(AUTOJIT_BUILD_UNIFIED)
  if(NOT DEFINED AUTOJIT_BUILTINS_LIB)
    if(NOT "compiler-rt" IN_LIST LLVM_ENABLE_RUNTIMES AND NOT LLVM_ENABLE_RUNTIMES STREQUAL "all")
      message(FATAL_ERROR "llvm-autojit requires compiler-rt: add it to "
                          "LLVM_ENABLE_RUNTIMES or set AUTOJIT_BUILTINS_LIB.")
    endif()
    # Runtimes build after we configure, so we can't check that it exists
    set(AUTOJIT_BUILTINS_FROM_RUNTIMES On)
    set(rt_dir ${LLVM_BINARY_DIR}/lib/clang/${LLVM_VERSION_MAJOR}/lib)
    if(LLVM_ENABLE_PER_TARGET_RUNTIME_DIR)
      set(AUTOJIT_BUILTINS_LIB ${rt_dir}/${LLVM_DEFAULT_TARGET_TRIPLE}/libclang_rt.builtins.a)
    else()
      set(AUTOJIT_BUILTINS_LIB ${rt_dir}/linux/libclang_rt.builtins-${CMAKE_SYSTEM_PROCESSOR}.a)
    endif()
  endif()
else()
  if(NOT DEFINED AUTOJIT_BUILTINS_LIB)
    execute_process(
      COMMAND ${LLVM_TOOLS_BINARY_DIR}/clang --rtlib=compiler-rt -print-libgcc-file-name
      OUTPUT_VARIABLE AUTOJIT_BUILTINS_LIB
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET)
  endif()
  if(NOT EXISTS "${AUTOJIT_BUILTINS_LIB}")
    message(FATAL_ERROR "compiler-rt builtins not found for LLVM ${LLVM_VERSION_MAJOR} "
                        "in ${LLVM_TOOLS_BINARY_DIR}: '${AUTOJIT_BUILTINS_LIB}'. Install "
                        "compiler-rt or set AUTOJIT_BUILTINS_LIB.")
  endif()
endif()

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/AutoJITConfig.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/AutoJITConfig.h
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

if(AUTOJIT_ENABLE_TPDE)
  add_compile_options(-Wno-unused-parameter)
  set(TPDE_LINK_LLVM_STATIC On)
  # TPDE gets linked into the shared autojit-runtime
  set(CMAKE_POSITION_INDEPENDENT_CODE On)
  # Pass TPDE_TARGETS if the LLVM we build against lacks X86 or AArch64
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
