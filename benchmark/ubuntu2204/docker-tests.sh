#!/usr/bin/env bash
set -xeuo pipefail

cmake -GNinja -Bbuild -Sllvm-autojit -DCMAKE_BUILD_TYPE=RelWithDebInfo -DAUTOJIT_ENABLE_ORC_RUNTIME=On
ninja -C build -v check-autojit
