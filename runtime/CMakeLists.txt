if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
endif()

if(AUTOJIT_ENABLE_ORC_RUNTIME)
  # Build runtime: ninja -C runtimes/runtimes-bins orc_rt-x86_64
  set(orc_rt_path ${CMAKE_BINARY_DIR}/lib/clang/20/lib/x86_64-unknown-linux-gnu/liborc_rt.a)
  add_custom_command(
    OUTPUT liborc_rt
    COMMAND ${CMAKE_COMMAND} -E copy ${orc_rt_path} ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt
    DEPENDS ${orc_rt_path}
    COMMENT "Copy ${orc_rt_path} -> ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt"
  )
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt.o
    COMMAND objcopy --input binary --output elf64-x86-64 --binary-architecture i386 liborc_rt ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt.o
    DEPENDS liborc_rt
    COMMENT "Convert ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt.a -> ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt.o"
  )
  add_custom_target(embed_orc_rt DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt
    ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt.o
  )

  set(orc_rt ${CMAKE_CURRENT_BINARY_DIR}/liborc_rt.o)
endif()

add_llvm_library(autojit-runtime SHARED
  AutoJITRuntime.cpp

  LINK_COMPONENTS
    BitcodeReader
    Core
    ExecutionEngine
    MCJIT
    Native
    Support
    Target

  LINK_LIBS
    ${tpde_libs}
    ${orc_rt}
  )

if(AUTOJIT_ENABLE_ORC_RUNTIME)
  add_dependencies(autojit-runtime embed_orc_rt)
endif()

# Root directory has the generated config header
target_include_directories(autojit-runtime PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
target_link_options(autojit-runtime PRIVATE -Wl,-Bsymbolic)
