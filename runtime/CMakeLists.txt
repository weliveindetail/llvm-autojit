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

llvm_map_components_to_libnames(llvm_libs
  BitReader
  BitstreamReader
  Core
  IRReader
  JITLink
  native
  OrcDebugging
  OrcJIT
  OrcTargetProcess
  Passes
  Support
  TargetParser
)

add_library(autojit-runtime SHARED AutoJITRuntime.cpp ${orc_rt})
set_target_properties(autojit-runtime PROPERTIES
  VERSION "${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}"
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

target_include_directories(autojit-runtime PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
target_link_libraries(autojit-runtime PRIVATE ${llvm_libs} ${tpde_libs})
target_link_options(autojit-runtime PRIVATE
  -Wl,-z,defs
  -Wl,-Bsymbolic
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.txt
)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojit-runtime PRIVATE -fno-rtti -fno-exceptions)
endif()

if(AUTOJIT_ENABLE_ORC_RUNTIME)
  add_dependencies(autojit-runtime embed_orc_rt)
endif()

install(
  TARGETS autojit-runtime
  LIBRARY DESTINATION lib${LLVM_LIBDIR_SUFFIX}
  COMPONENT autojit-runtime
)

add_custom_target(install-autojit-runtime
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-runtime
  COMMENT "Installing AutoJIT runtime"
)
