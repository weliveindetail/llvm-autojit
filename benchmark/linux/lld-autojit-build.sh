#!/usr/bin/env bash
set -e

AUTOJIT_BUILD_DIR="${AUTOJIT_BUILD_DIR:-build_autojit}"

# Keep lazy modules in the build tree, /tmp is shared with all other builds
export AUTOJIT_DIR="$(pwd)/lld/$AUTOJIT_BUILD_DIR/autojit"

echo "Building autojit lld.."
ninja -C lld/$AUTOJIT_BUILD_DIR lld
