if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
endif()

if(AUTOJIT_EMBED_ORC_RUNTIME)
  set(clang_rt_libs clang/${LLVM_VERSION_MAJOR}/lib)
  if (AUTOJIT_BUILD_UNIFIED)
    # Build runtime: ninja -C runtimes/runtimes-bins orc_rt-x86_64
    set(orc_rt_path ${CMAKE_BINARY_DIR}/lib/${clang_rt_libs}/x86_64-unknown-linux-gnu/liborc_rt.a)
  endif()
  if(AUTOJIT_BUILD_EXTERNAL)
    # apt packages for clang up to 21 have LLVM_ENABLE_PER_TARGET_RUNTIME_DIR=Off
    set(orc_rt_path ${LLVM_BINARY_DIR}/lib/${clang_rt_libs}/linux/liborc_rt-x86_64.a)
  endif()

  if (orc_rt_path)
    message(STATUS "Found: ${orc_rt_path}")
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
  else()
    message(WARNING "liborc_rt not found")
  endif()
endif()

# The runtime must not resolve symbols from shared libraries that programs
# might define themselves, e.g. a program that builds its own zlib with autojit.
# The executable would export its lazy definitions and they would interpose the
# ones from the shared library. LLVM's compression support pulls in zlib and
# zstd, so we link them statically and hide their symbols (--exclude-libs).
option(AUTOJIT_STATIC_COMPRESSION_LIBS
       "Link zlib and zstd statically into the runtime, if available" ON)
if(AUTOJIT_STATIC_COMPRESSION_LIBS)
  foreach(entry IN ITEMS "ZLIB::ZLIB=libz.a" "zstd::libzstd_shared=libzstd.a")
    string(REPLACE "=" ";" entry "${entry}")
    list(GET entry 0 imported_target)
    list(GET entry 1 archive_name)
    if(TARGET ${imported_target})
      find_library(static_lib_${archive_name} NAMES ${archive_name})
      if(static_lib_${archive_name})
        message(STATUS "Link ${imported_target} statically: ${static_lib_${archive_name}}")
        get_target_property(configs ${imported_target} IMPORTED_CONFIGURATIONS)
        set_target_properties(${imported_target} PROPERTIES
          IMPORTED_LOCATION "${static_lib_${archive_name}}")
        foreach(config IN LISTS configs)
          set_target_properties(${imported_target} PROPERTIES
            IMPORTED_LOCATION_${config} "${static_lib_${archive_name}}")
        endforeach()
      else()
        message(WARNING "${archive_name} not found, runtime links ${imported_target} dynamically")
      endif()
    endif()
  endforeach()
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

# Static stub: pure C, no LLVM deps
#
# Each variant is a single relocatable object, so it's linked as a whole. The
# daemon looks up symbols by name in the stub process, which aren't referenced
# statically. The library itself is an implicit linker script that adds the
# object to the link.
set(autojit_stub_outputs)

function(add_autojit_stub name)
  cmake_parse_arguments(ARG "" "" "SOURCES;DEFINES" ${ARGN})
  set(lib_name ${name}-${CMAKE_SYSTEM_PROCESSOR})
  set(obj_file ${CMAKE_BINARY_DIR}/lib/${lib_name}.o)
  set(script_file ${CMAKE_BINARY_DIR}/lib/lib${lib_name}.a)

  add_library(${name}-objs OBJECT ${ARG_SOURCES})
  set_target_properties(${name}-objs PROPERTIES C_STANDARD 11)
  target_compile_definitions(${name}-objs PRIVATE ${ARG_DEFINES})
  target_compile_options(${name}-objs PRIVATE -Wno-cast-qual)
  if(AUTOJIT_SANITIZE)
    target_compile_options(${name}-objs PRIVATE -fsanitize=${AUTOJIT_SANITIZE})
  endif()

  add_custom_command(
    OUTPUT ${obj_file}
    COMMAND ${CMAKE_C_COMPILER} -r -nostdlib $<TARGET_OBJECTS:${name}-objs> -o ${obj_file}
    DEPENDS $<TARGET_OBJECTS:${name}-objs>
    COMMAND_EXPAND_LISTS
    COMMENT "Linking relocatable object ${lib_name}.o"
  )
  file(WRITE ${script_file}
    "/* Implicit linker script: link the AutoJIT stub object as a whole */\n"
    "INPUT(${lib_name}.o)\n"
  )

  install(
    FILES ${obj_file} ${script_file}
    DESTINATION lib
    COMPONENT autojit-stub
  )
  set(autojit_stub_outputs ${autojit_stub_outputs} ${obj_file} PARENT_SCOPE)
endfunction()

# Default stub without debugger support
add_autojit_stub(autojit_static
  SOURCES remote/Stub.c remote/StubSPS.c
  DEFINES AUTOJIT_STUB_DEBUG_SUPPORT=0
)

# Stub with support for the GDB JIT interface
add_autojit_stub(autojit_static_debug
  SOURCES remote/Stub.c remote/StubDebug.c remote/StubSPS.c
  DEFINES AUTOJIT_STUB_DEBUG_SUPPORT=1
)

add_custom_target(autojit-stub ALL DEPENDS ${autojit_stub_outputs})

# Daemon executable
add_executable(autojitd
  remote/Daemon.cpp
  remote/Session.cpp
  core/AutoJIT.cpp
  core/ExecutorPlatform.cpp
  ${orc_rt}
)
set_target_properties(autojitd PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

target_link_libraries(autojitd PRIVATE ${llvm_libs} ${tpde_libs})

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojitd PRIVATE -fno-rtti -fno-exceptions)
endif()

if(AUTOJIT_EMBED_ORC_RUNTIME)
  add_dependencies(autojitd embed_orc_rt)
endif()
if(AUTOJIT_SANITIZE)
  target_compile_options(autojitd PRIVATE -fsanitize=${AUTOJIT_SANITIZE})
  target_link_options(autojitd PRIVATE -fsanitize=${AUTOJIT_SANITIZE})
endif()

install(
  TARGETS autojitd
  RUNTIME DESTINATION bin
  COMPONENT autojitd
)

# Shared library
add_library(autojit-so SHARED
  inprocess/Shlib.cpp
  core/AutoJIT.cpp
  core/ExecutorPlatform.cpp
  ${orc_rt}
)
set_target_properties(autojit-so PROPERTIES
  LIBRARY_OUTPUT_NAME "autojit-runtime"
  VERSION "${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}"
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

target_link_libraries(autojit-so PRIVATE ${llvm_libs} ${tpde_libs})

# The runtime must not call into lazy code of the executable, because it would
# re-enter materialization. The executable exports its own definitions of
# libstdc++ symbols (e.g. template instantiations of std::string) and they
# interpose the ones from libstdc++.so. So we link a private copy of the C++
# standard library and resolve all references within the runtime. Its
# unwinder is private as well, so we never pull libgcc_s into programs
# that use libunwind. We register EH frames of JITed code with the program's
# unwinder, which we look up at run-time (see common/EHFrames.h).
target_link_options(autojit-so PRIVATE
  -static-libstdc++
  -static-libgcc
  -Wl,--exclude-libs,ALL
  -Wl,-z,defs
  -Wl,-Bsymbolic
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.txt
)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojit-so PRIVATE -fno-rtti -fno-exceptions)
endif()

if(AUTOJIT_EMBED_ORC_RUNTIME)
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
