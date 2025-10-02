# Detect OS and include appropriate benchmark scripts
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # Detect Linux distribution and version
  if(EXISTS "/etc/os-release")
    file(READ "/etc/os-release" OS_RELEASE)
    if(OS_RELEASE MATCHES "Ubuntu.*22\\.04")
      add_subdirectory(ubuntu2204)
    endif()
  endif()
endif()

if(TARGET install-autojit-bench-scripts)
  install(DIRECTORY inputs
    DESTINATION benchmark
    COMPONENT autojit-bench-inputs
  )
  add_custom_target(install-autojit-bench
    COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-bench-inputs
    COMMENT "Installing AutoJIT benchmark"
  )
  add_dependencies(install-autojit-bench
    install-autojit
    install-autojit-runtime
    install-autojit-bench-scripts
  )
  if(AUTOJIT_BUILD_UNIFIED)
    add_dependencies(install-autojit-bench
      install-clang
      install-clang-cpp
      install-clang-resource-headers
      install-compiler-rt
      install-LLVM
      install-opt
      install-lld
    )
  endif()
endif()
