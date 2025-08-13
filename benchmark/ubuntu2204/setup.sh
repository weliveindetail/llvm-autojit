#!/usr/bin/env bash
set -e

if [ ! -d "llvm-autojit-bench" ]; then
    echo "Fetching benchmark code.."
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
