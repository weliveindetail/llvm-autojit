#!/usr/bin/env bash

rm -rf bzip2/build_autojit
cp -r llvm-autojit-bench/original/401.bzip2/bzip2-1.0.3 \
      bzip2/build_autojit
