#!/usr/bin/env bash
set -e

echo "Test FileCheck with autojit"
mkdir -p FileCheck
rm -rf FileCheck/build_autojit
rm -rf /tmp/autojit_*.ll

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=1

echo "Configure: FileCheck/test-autojit-setup.log"
./FileCheck-autojit-setup.sh > FileCheck/test-autojit-setup.log 2>&1
echo "Build: FileCheck/test-autojit-build.log"
./FileCheck-autojit-build.sh > FileCheck/test-autojit-build.log 2>&1
echo "Run: FileCheck/test-autojit-run.log"
./FileCheck/build_autojit/bin/FileCheck --version > FileCheck/test-autojit-run.log 2>&1
