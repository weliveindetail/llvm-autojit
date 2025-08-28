#!/usr/bin/env bash
set -e

echo "Test bzip2 with autojit"
rm -rf bzip2
rm -rf /tmp/autojit_*.ll
mkdir bzip2

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=1

echo "Configure: bzip2/test-autojit-setup.log"
./bzip2-autojit-setup.sh > bzip2/test-autojit-setup.log 2>&1
echo "Build: bzip2/test-autojit-build.log"
./bzip2-autojit-build.sh > bzip2/test-autojit-build.log 2>&1
echo "Run: bzip2/test-autojit-run.log"
./bzip2/build_autojit/bzip2 --help 2> bzip2/test-autojit-run.log

mkdir -p bzip2/outputs
cp inputs/data1.txt bzip2/outputs/data1_autojit.txt
./bzip2/build_autojit/bzip2 --compress bzip2/outputs/data1_autojit.txt 2>> bzip2/test-autojit-run.log
