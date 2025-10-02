#!/usr/bin/env bash
set -e

echo "Test FileCheck with autojit"
mkdir -p FileCheck
rm -rf FileCheck/build_autojit
rm -rf /tmp/autojit_*.ll

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=1

echo "Configure: FileCheck/test-autojit-setup.log"
./FileCheck-autojit-setup.sh > FileCheck/test-autojit-setup.log 2>&1
echo "Build: FileCheck/test-autojit-build.log"
./FileCheck-autojit-build.sh > FileCheck/test-autojit-build.log 2>&1

# Link again with --whole-archive
"/home/ez/Develop/llvm-project-main/build-install/bin/ld.lld" "-z" "relro" "--hash-style=gnu" "--eh-frame-hdr" "-m" "elf_x86_64" "-export-dynamic" "-pie" "-dynamic-linker" "/lib64/ld-linux-x86-64.so.2" "-o" "FileCheck/build_autojit/bin/FileCheck" "/lib/x86_64-linux-gnu/Scrt1.o" "/lib/x86_64-linux-gnu/crti.o" "/usr/lib/gcc/x86_64-linux-gnu/13/crtbeginS.o" "-L/home/ez/Develop/llvm-project-main/build-install/lib" "-L/home/ez/Develop/llvm-project-main/build-install/lib/clang/20/lib/x86_64-unknown-linux-gnu" "-L/usr/lib/gcc/x86_64-linux-gnu/13" "-L/usr/lib/gcc/x86_64-linux-gnu/13/../../../../lib64" "-L/lib/x86_64-linux-gnu" "-L/lib/../lib64" "-L/usr/lib/x86_64-linux-gnu" "-L/usr/lib/../lib64" "-L/lib" "-L/usr/lib" "-rpath=/home/ez/Develop/llvm-project-main/build-install/lib" "--no-gc-sections" "-lautojit-runtime" "--color-diagnostics" "FileCheck/build_autojit/utils/FileCheck/CMakeFiles/FileCheck.dir/FileCheck.cpp.o" "-rpath" "\$ORIGIN/../lib" --whole-archive "FileCheck/build_autojit/lib/libLLVMFileCheck.a" "FileCheck/build_autojit/lib/libLLVMSupport.a" --no-whole-archive "-lrt" "-ldl" "-lm" "/usr/lib/x86_64-linux-gnu/libz.so" "/usr/lib/x86_64-linux-gnu/libzstd.so" --whole-archive "FileCheck/build_autojit/lib/libLLVMDemangle.a" --no-whole-archive "-lc++" "-lm" "-lgcc_s" "-lgcc" "-lc" "-lgcc_s" "-lgcc" "/usr/lib/gcc/x86_64-linux-gnu/13/crtendS.o" "/lib/x86_64-linux-gnu/crtn.o"

echo "Run: FileCheck/test-autojit-run.log"
./FileCheck/build_autojit/bin/FileCheck --version > FileCheck/test-autojit-run.log 2>&1
