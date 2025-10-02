#!/usr/bin/env bash
set -e

if [ ! -d "llvm-autojit-bench" ]; then
    echo "Fetching benchmark code.."
    git clone https://github.com/weliveindetail/llvm-autojit-bench
fi

if [ ! -d "llvm-project" ]; then
    echo "Fetching benchmark code.."
    git clone https://github.com/llvm/llvm-project
fi
