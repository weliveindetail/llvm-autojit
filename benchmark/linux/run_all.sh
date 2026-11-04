#!/usr/bin/env bash
set -e

if [ ! -d "llvm-autojit-bench" ] || [ ! -d "inputs" ]; then
    ./setup.sh
fi

rm -rf bzip2
./bzip2.sh

rm -rf FileCheck
./FileCheck.sh
