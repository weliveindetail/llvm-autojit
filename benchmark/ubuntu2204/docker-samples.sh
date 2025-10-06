#!/usr/bin/env bash
set -xeuo pipefail

cmake -GNinja -Bbuild -Sllvm-autojit -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/workspace/install
ninja -C build install-autojit-bench

# This is no unified build, but we need symlink the LLVM tools dir into the install root
#llvm_bin=$(clang --version | tail -n1 | awk '{print $NF}')
#ln -sfn "$llvm_bin" install/bin

cd install/benchmark
./setup.sh
./bzip2-test.sh
