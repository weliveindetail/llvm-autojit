#!/usr/bin/env bash

mkdir -p bzip2
rm -rf bzip2/build_regular
cp -r llvm-autojit-bench/specCPU2006/original/401.bzip2/bzip2-1.0.3 \
      bzip2/build_regular
