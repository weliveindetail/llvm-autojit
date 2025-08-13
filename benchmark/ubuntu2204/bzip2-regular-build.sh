#!/usr/bin/env bash

export CC="$(pwd)/../bin/clang"
export CXX="$(pwd)/../bin/clang++"
export CFLAGS="-O0 -g"
export LDFLAGS="-fuse-ld=lld -B$(pwd)/../bin"

cd bzip2/build_regular
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
