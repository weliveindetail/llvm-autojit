#!/usr/bin/env bash
set -xeuo pipefail

cd /workspace
cmake -GNinja -Bbuild -Sllvm-autojit \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/workspace/install \
      -DAUTOJIT_ENABLE_ORC_RUNTIME=On
ninja -C build install-autojit-bench

export AUTOJITD_FORCE_SPAWN=On
export AUTOJITD_FORCE_DAEMON=Off
export AUTOJIT_LINK_STATIC_RUNTIME=On
export AUTOJIT_BUILD_DIR=build_autojit_static
export AUTOJIT_DAEMON_PATH=/workspace/install/bin/autojitd

cd /workspace/install/benchmark
./setup.sh
./bzip2-test.sh
./json-test.sh

if command -v rustc >/dev/null 2>&1; then
  ./hello-rs-test.sh
fi
