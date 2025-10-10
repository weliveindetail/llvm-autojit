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

# Static stub library: pure C, no LLVM deps
add_library(autojit-stub STATIC AutoJITRuntimeStub.c AutoJITDebug.c)
set_target_properties(autojit-stub PROPERTIES
  OUTPUT_NAME "autojit_static-${CMAKE_SYSTEM_PROCESSOR}"
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  C_STANDARD 11
)

target_include_directories(autojit-stub PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
target_link_libraries(autojit-stub PRIVATE pthread)
target_compile_options(autojit-stub PRIVATE -Wno-cast-qual)

install(
  TARGETS autojit-stub
  ARCHIVE DESTINATION lib
  COMPONENT autojit-stub
)

# Daemon executable
add_executable(autojitd AutoJITDaemon.cpp AutoJITCommon.cpp ${orc_rt})
set_target_properties(autojitd PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

target_include_directories(autojitd PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
target_link_libraries(autojitd PRIVATE ${llvm_libs} ${tpde_libs})

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojitd PRIVATE -fno-rtti -fno-exceptions)
endif()

if(AUTOJIT_ENABLE_ORC_RUNTIME)
  add_dependencies(autojitd embed_orc_rt)
endif()

install(
  TARGETS autojitd
  RUNTIME DESTINATION bin
  COMPONENT autojitd
)

# Shared library
add_library(autojit-so SHARED AutoJITRuntimeSO.cpp AutoJITCommon.cpp ${orc_rt})
set_target_properties(autojit-so PROPERTIES
  LIBRARY_OUTPUT_NAME "autojit-runtime"
  VERSION "${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}"
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

target_include_directories(autojit-so PRIVATE ${AUTOJIT_CONFIG_FILE_DIR})
target_link_libraries(autojit-so PRIVATE ${llvm_libs} ${tpde_libs})
target_link_options(autojit-so PRIVATE
  -Wl,-z,defs
  -Wl,-Bsymbolic
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.txt
)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojit-so PRIVATE -fno-rtti -fno-exceptions)
endif()

if(AUTOJIT_ENABLE_ORC_RUNTIME)
  add_dependencies(autojit-so embed_orc_rt)
endif()

install(
  TARGETS autojit-so
  LIBRARY DESTINATION lib
  COMPONENT autojit-so
)

add_custom_target(install-autojit-so
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-so
  COMMENT "Installing AutoJIT shared library"
)

add_custom_target(install-autojit-stub
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojit-stub
  COMMENT "Installing AutoJIT stub library"
)

add_custom_target(install-autojitd
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --component autojitd
  COMMENT "Installing AutoJIT daemon"
)

add_dependencies(install-autojit-so autojit-so)
add_dependencies(install-autojit-stub autojit-stub)
add_dependencies(install-autojitd autojitd)

add_custom_target(autojit-runtime)
add_dependencies(autojit-runtime autojit-so autojit-stub autojitd)

add_custom_target(install-autojit-runtime)
add_dependencies(install-autojit-runtime install-autojit-so install-autojit-stub install-autojitd)
