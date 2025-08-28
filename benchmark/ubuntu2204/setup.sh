#!/usr/bin/env bash
set -e

if [ ! -d "llvm-autojit-bench" ]; then
    echo "Fetching benchmark code.."
    git clone https://github.com/weliveindetail/llvm-autojit-bench llvm-autojit-bench
fi
