#!/bin/bash
set -e

if [ ! -d "llvm-autojit-bench" ]; then
    git clone https://github.com/weliveindetail/llvm-autojit-bench llvm-autojit-bench
fi

if [ ! -d "inputs" ]; then
    echo "Generating test files.."
    mkdir inputs
    # Up to 10MB
    for i in {1..2}; do
        head -c $((1024 * 1024 * 5 * i)) /dev/urandom | base64 > inputs/data${i}.txt
    done
fi

export CC="$(pwd)/../bin/clang"
export CXX="$(pwd)/../bin/clang++"
export CFLAGS="-O0 -g"
export LDFLAGS="-fuse-ld=lld -B$(pwd)/../bin"
export AUTOJIT_PLUGIN="$(pwd)/../lib/autojit.so"
export AUTOJIT_RUNTIME_DIR="$(pwd)/../lib"

rm -rf bzip2
./bzip2.sh
