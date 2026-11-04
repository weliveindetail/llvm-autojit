if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_subdirectory(linux)
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
