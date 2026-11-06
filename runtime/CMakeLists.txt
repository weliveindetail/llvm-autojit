if(AUTOJIT_ENABLE_TPDE)
  set(tpde_libs tpde_llvm)
endif()

# The in-process runtime links zlib and zstd statically, so that programs with
# their own copies don't interpose them (see below). In-tree builds share
# LLVMSupport with libLLVM.so and the tools, so we swap them only for autojit-so.
function(autojit_so_link_static libs_var shared_lib static_lib)
  if(NOT static_lib)
    message(FATAL_ERROR "LLVM uses ${shared_lib}, but the in-process runtime "
                        "needs a static library for it")
  endif()
  set(is_autojit_so "$<STREQUAL:$<TARGET_PROPERTY:NAME>,autojit-so>")
  set(replacement "$<IF:${is_autojit_so},${static_lib},${shared_lib}>")
  set(libs "${${libs_var}}")
  # In-tree builds wrap the private dependencies of static libraries
  list(TRANSFORM libs REPLACE "^${shared_lib}$" "${replacement}")
  list(TRANSFORM libs REPLACE
    "^\\$<LINK_ONLY:${shared_lib}>$" "$<LINK_ONLY:${replacement}>")
  set(${libs_var} "${libs}" PARENT_SCOPE)
endfunction()

get_target_property(support_libs LLVMSupport INTERFACE_LINK_LIBRARIES)
if(TARGET ZLIB::ZLIB)
  find_library(ZLIB_STATIC_LIBRARY NAMES libz.a)
  autojit_so_link_static(support_libs ZLIB::ZLIB "${ZLIB_STATIC_LIBRARY}")
endif()
if(TARGET zstd::libzstd_shared)
  # LLVM's Findzstd and zstd's own CMake package provide it, if available
  if(TARGET zstd::libzstd_static)
    set(zstd_static_target zstd::libzstd_static)
  endif()
  autojit_so_link_static(support_libs zstd::libzstd_shared "${zstd_static_target}")
endif()
set_target_properties(LLVMSupport PROPERTIES INTERFACE_LINK_LIBRARIES "${support_libs}")

# Static stub: pure C, no LLVM deps
#
# Each variant is a single relocatable object, so it's linked as a whole. The
# daemon looks up symbols by name in the stub process, which aren't referenced
# statically. There are two ways to add it to a link. The archive is for .deplibs:
# lld adds dependent libraries once per object, but pulls the member only once.
# The _ldscript library is an implicit linker script for -l, so it works at any
# position on the link line.
set(autojit_stub_outputs)

function(add_autojit_stub name)
  cmake_parse_arguments(ARG "" "" "SOURCES;DEFINES" ${ARGN})
  set(obj_file ${CMAKE_BINARY_DIR}/lib/${name}.o)
  set(script_file ${CMAKE_BINARY_DIR}/lib/lib${name}_ldscript.a)
  set(archive_file ${CMAKE_BINARY_DIR}/lib/lib${name}.a)

  add_library(${name}-objs OBJECT ${ARG_SOURCES})
  # The stub also links into shared libraries
  set_target_properties(${name}-objs PROPERTIES
    C_STANDARD 11
    POSITION_INDEPENDENT_CODE On
  )
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
    COMMENT "Linking relocatable object ${name}.o"
  )
  add_custom_command(
    OUTPUT ${archive_file}
    COMMAND ${CMAKE_AR} rcs ${archive_file} ${obj_file}
    DEPENDS ${obj_file}
    COMMENT "Creating archive lib${name}.a"
  )
  file(WRITE ${script_file}
    "/* Implicit linker script: link the AutoJIT stub object as a whole */\n"
    "INPUT(${name}.o)\n"
  )

  install(
    FILES ${obj_file} ${script_file} ${archive_file}
    DESTINATION lib
    COMPONENT autojit-stub
  )
  set(autojit_stub_outputs ${autojit_stub_outputs} ${obj_file} ${archive_file} PARENT_SCOPE)
endfunction()

# Resolver for lean trampolines, the plugin only emits them for these
set(autojit_resolver)
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  set(autojit_resolver common/ResolverX86_64.c)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  set(autojit_resolver common/ResolverAArch64.c)
endif()

# Default stub without debugger support
add_autojit_stub(autojit_static
  SOURCES remote/Stub.c remote/StubSPS.c ${autojit_resolver}
  DEFINES AUTOJIT_STUB_DEBUG_SUPPORT=0
)

# Stub with support for the GDB JIT interface
add_autojit_stub(autojit_static_debug
  SOURCES remote/Stub.c remote/StubDebug.c remote/StubSPS.c
          ${autojit_resolver}
  DEFINES AUTOJIT_STUB_DEBUG_SUPPORT=1
)

# Shared stub, e.g. for .deplibs with AUTOJIT_RUNTIME at compile time
function(add_autojit_stub_so name)
  cmake_parse_arguments(ARG "" "" "SOURCES;DEFINES" ${ARGN})
  add_library(${name}-so SHARED ${ARG_SOURCES})
  set_target_properties(${name}-so PROPERTIES
    C_STANDARD 11
    LIBRARY_OUTPUT_NAME ${name}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    NO_SONAME On
  )
  target_compile_definitions(${name}-so PRIVATE ${ARG_DEFINES})
  target_compile_options(${name}-so PRIVATE -Wno-cast-qual)
  # Programs must not interpose the stub's internals
  target_link_options(${name}-so PRIVATE -Wl,-Bsymbolic)
  install(
    TARGETS ${name}-so
    LIBRARY DESTINATION lib
    COMPONENT autojit-stub
  )
endfunction()

add_autojit_stub_so(autojit-stub
  SOURCES remote/Stub.c remote/StubSPS.c ${autojit_resolver}
  DEFINES AUTOJIT_STUB_DEBUG_SUPPORT=0
)
add_autojit_stub_so(autojit-stub-debug
  SOURCES remote/Stub.c remote/StubDebug.c remote/StubSPS.c ${autojit_resolver}
  DEFINES AUTOJIT_STUB_DEBUG_SUPPORT=1
)

add_custom_target(autojit-stub ALL
  DEPENDS ${autojit_stub_outputs} autojit-stub-so autojit-stub-debug-so)

# Executor process control for the LLVM version we build against
if(AUTOJIT_LLVM_LEGACY)
  set(autojit_remote_epc remote/LegacyRemoteEPC.cpp)
else()
  set(autojit_remote_epc remote/DefaultRemoteEPC.cpp)
endif()

# Daemon executable
# The copy gives us a target to depend on. Unified builds produce the original in
# the runtimes build, which runs after we configure.
set(builtins_copy ${CMAKE_CURRENT_BINARY_DIR}/builtins.a)
add_custom_target(autojit-builtins
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${AUTOJIT_BUILTINS_LIB} ${builtins_copy}
  BYPRODUCTS ${builtins_copy}
  COMMENT "Update embedded compiler builtins"
)
if(AUTOJIT_BUILTINS_FROM_RUNTIMES)
  add_dependencies(autojit-builtins runtimes)
endif()
set_source_files_properties(core/BuiltinsArchive.cpp PROPERTIES
  COMPILE_DEFINITIONS "AUTOJIT_BUILTINS_ARCHIVE=\"${builtins_copy}\""
  OBJECT_DEPENDS ${builtins_copy}
)

add_executable(autojitd
  remote/Daemon.cpp
  remote/Session.cpp
  core/AutoJIT.cpp
  core/BuiltinsArchive.cpp
  core/ExecutorPlatform.cpp
  ${autojit_remote_epc}
)
set_target_properties(autojitd PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

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

target_link_libraries(autojitd PRIVATE ${llvm_libs} ${tpde_libs})
add_dependencies(autojitd autojit-builtins)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojitd PRIVATE -fno-rtti -fno-exceptions)
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
  ${autojit_resolver}
  core/AutoJIT.cpp
  core/BuiltinsArchive.cpp
  core/ExecutorPlatform.cpp
)
set_target_properties(autojit-so PROPERTIES
  LIBRARY_OUTPUT_NAME "autojit-runtime"
  VERSION "${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}"
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  # AUTOJIT_RUNTIME passes the absolute path in .deplibs. With a soname, programs
  # would record that instead and need an rpath to start.
  NO_SONAME On
)

target_link_libraries(autojit-so PRIVATE ${llvm_libs} ${tpde_libs})
add_dependencies(autojit-so autojit-builtins)

# The in-process runtime must not call lazy code in the executable, it would
# re-enter materialization. So it links private copies of libstdc++ and the
# unwinder (see common/EHFrames.h for JITed code) and binds all references
# locally. exports.txt hides their symbols; --exclude-libs would also hide the
# GDB JIT interface.
target_link_options(autojit-so PRIVATE
  -static-libstdc++
  -static-libgcc
  -Wl,-z,defs
  -Wl,-Bsymbolic
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.txt
)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(autojit-so PRIVATE -fno-rtti -fno-exceptions)
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
