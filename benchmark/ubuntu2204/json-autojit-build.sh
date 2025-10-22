#!/usr/bin/env bash

echo "Building autojit binary.."
ninja -C json/$AUTOJIT_BUILD_DIR tests/all
