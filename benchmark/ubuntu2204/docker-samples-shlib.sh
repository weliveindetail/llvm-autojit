#!/usr/bin/env bash
set -xeuo pipefail

cd /workspace
cmake -GNinja -Bbuild -Sllvm-autojit \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/workspace/install \
      -DAUTOJIT_ENABLE_ORC_RUNTIME=On
ninja -C build install-autojit-bench

export AUTOJITD_FORCE_SPAWN=Off
export AUTOJITD_FORCE_DAEMON=On
export AUTOJIT_LINK_STATIC_RUNTIME=Off
export AUTOJIT_BUILD_DIR=build_autojit_shlib

cd /workspace/install/benchmark
./setup.sh
./bzip2-test.sh

if command -v rustc >/dev/null 2>&1; then
  ./hello-rs-test.sh
fi
