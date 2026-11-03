#!/usr/bin/env bash

# Keep lazy modules in the build tree, /tmp is shared with all other builds
export AUTOJIT_DIR="$(pwd)/json/$AUTOJIT_BUILD_DIR/autojit"

echo "Building autojit binary.."
ninja -C json/$AUTOJIT_BUILD_DIR tests/test-hash_cpp11
