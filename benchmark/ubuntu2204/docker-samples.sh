#!/usr/bin/env bash
set -xeuo pipefail

cmake -GNinja -Bbuild -Sllvm-autojit -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/workspace/install -DAUTOJIT_ENABLE_ORC_RUNTIME=On
ninja -C build install-autojit-bench

cd install/benchmark
./setup.sh
./bzip2-test.sh
./bzip2-test.sh --autojitd=/workspace/install/bin/autojitd

if command -v rustc >/dev/null 2>&1; then
  ./hello-rs-test.sh
fi
