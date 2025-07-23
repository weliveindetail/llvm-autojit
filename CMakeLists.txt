
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

if(NOT DEFINED LLVM_MAIN_SRC_DIR)
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

# Add subdirectories for plugin and runtime
add_subdirectory(plugin)
add_subdirectory(runtime)

# Create a master install target that depends on the LLVM-generated install targets
# add_llvm_pass_plugin creates an install-autojit target automatically
# add_llvm_library creates an install-autojit-runtime target automatically

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

add_dependencies(install-autojit install-autojit-runtime install-autojit-headers)

# TODO: Detect and support other hosts
file(GLOB BENCH_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/benchmark/ubuntu2204/*.sh")
message(${BENCH_SCRIPTS})
install(PROGRAMS ${BENCH_SCRIPTS}
  DESTINATION benchmark
  COMPONENT autojit-bench-scripts
)

add_custom_target(install-autojit-bench
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-bench-scripts
  COMMENT "Installing AutoJIT benchmark"
)

add_dependencies(install-autojit-bench install-autojit install-LLVM install-clang install-clang-cpp install-clang-resource-headers install-lld)

# Add testing support
if(NOT DEFINED LLVM_MAIN_SRC_DIR)
  # External build - find lit
  find_program(LIT_COMMAND lit)
  if(LIT_COMMAND)
    add_custom_target(check-autojit
      COMMAND ${LIT_COMMAND} ${CMAKE_CURRENT_SOURCE_DIR}/test
      DEPENDS autojit
      COMMENT "Running AutoJIT tests"
    )
  else()
    message(WARNING "lit not found - tests will not be available")
  endif()
else()
  # Building as part of LLVM unified build
  add_subdirectory(test)
endif()
