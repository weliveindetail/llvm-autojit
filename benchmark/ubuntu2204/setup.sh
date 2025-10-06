#!/usr/bin/env bash
set -e

if [ ! -d "llvm-autojit-bench" ]; then
    echo "Fetching benchmark code.."
    git clone --depth 1 https://github.com/weliveindetail/llvm-autojit-bench
fi
