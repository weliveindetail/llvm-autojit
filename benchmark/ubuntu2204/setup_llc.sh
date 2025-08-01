#!/bin/bash
set -e

export CCACHE_DISABLE=1
LLVM_PROJECT_DIR="$1"

echo "Setting up benchmark llc"
mkdir -p llc && cd llc

## Regular bench
#echo "Building regular binary.."
#CC="$CC" CXX="$CXX" cmake -GNinja \
#    -S "$LLVM_PROJECT_DIR/llvm" \
#    -B "$build_regular" \
#    -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_LIBCXX=On \
#    -DCMAKE_C_FLAGS="$CFLAGS" \
#    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
#    -DLLVM_ENABLE_PROJECTS=clang -DLLVM_USE_LINKER=lld
#time ninja -C "$LLVM_PROJECT_DIR/build_regular" llc

# AutoJIT bench
echo "Building AutoJIT binary.."
CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" cmake --debug-trycompile -GNinja \
    -S $LLVM_PROJECT_DIR/llvm \
    -B build_autojit \
    -DCMAKE_VERBOSE_MAKEFILE=On \
    -DCMAKE_C_FLAGS="$CFLAGS -fpass-plugin=$AUTOJIT_PLUGIN" \
    -DCMAKE_CXX_FLAGS="$CFLAGS -fpass-plugin=$AUTOJIT_PLUGIN" \
    -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS -Wl,-rpath=$AUTOJIT_RUNTIME_DIR -Wl,--no-gc-sections -L$AUTOJIT_RUNTIME_DIR -lautojit-runtime -rdynamic" \
    -DCMAKE_BUILD_TYPE=Release
time ninja -C build_autojit llc

## Runtime bench
#rm -rf outputs
#mkdir outputs
#echo ""
#echo "Run-time regular:"
#for i in {1..2}; do
#    for _ in {1..10}; do
#        duration=$({ time build_regular/bzip2 -1 ../inputs/data${i}.txt --stdout > outputs/data${i}_regular.txt 2>/dev/null; } 2>&1 | grep real | awk '{print $2}')
#        hash=$(md5sum outputs/data${i}_regular.txt | awk '{print $1}')
#        echo "$duration $hash"
#    done
#done
#echo ""
#echo "Run-time autojit:"
#for i in {1..2}; do
#    for _ in {1..10}; do
#        duration=$({ time build_autojit/bzip2 -1 ../inputs/data${i}.txt --stdout > outputs/data${i}_autojit.txt 2>/dev/null; } 2>&1 | grep real | awk '{print $2}')
#        hash=$(md5sum outputs/data${i}_autojit.txt | awk '{print $1}')
#        echo "$duration $hash"
#    done
#done
