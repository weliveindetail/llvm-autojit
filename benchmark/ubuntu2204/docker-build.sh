#!/usr/bin/env bash
set -xeuo pipefail

cmake -GNinja -Bbuild -Sllvm-autojit -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/workspace
ninja -C build check-autojit
