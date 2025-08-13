#!/usr/bin/env bash

export CC="$(pwd)/../bin/clang"
export CXX="$(pwd)/../bin/clang++"
export CFLAGS="-O0 -g"
export LDFLAGS="-fuse-ld=lld -B$(pwd)/../bin"
export AUTOJIT_PLUGIN="$(pwd)/../lib/autojit.so"
export AUTOJIT_RUNTIME_DIR="$(pwd)/../lib"

cd bzip2/build_autojit
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS -fpass-plugin=$AUTOJIT_PLUGIN" LDFLAGS="$LDFLAGS -Wl,-rpath=$AUTOJIT_RUNTIME_DIR -Wl,--no-gc-sections -L$AUTOJIT_RUNTIME_DIR -lautojit-runtime -rdynamic"
