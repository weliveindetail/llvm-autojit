#!/usr/bin/env bash
set -e

echo "Building regular lld.."
ninja -C lld/build_regular lld
