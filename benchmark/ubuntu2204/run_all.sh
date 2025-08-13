#!/usr/bin/env bash
set -e

if [ ! -d "llvm-autojit-bench" ] || [ ! -d "inputs" ]; then
    ./setup.sh
fi

rm -rf bzip2
./bzip2.sh
exit 0

rm -rf llc
./setup_llc.sh $(pwd)/llvm-autojit-bench/llvm-project

rm -rf clang/build_autojit
./setup_clang.sh $(pwd)/llvm-autojit-bench/llvm-project
