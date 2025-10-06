#!/usr/bin/env bash
set -xeuo pipefail

echo "Test bzip2 with autojit"
rm -rf bzip2
rm -rf /tmp/autojit_*.ll
mkdir bzip2

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=1

./bzip2-autojit-setup.sh
./bzip2-autojit-build.sh
./bzip2/build_autojit/bzip2 --help

mkdir -p bzip2/outputs
cp inputs/data1.txt bzip2/outputs/test_autojit.txt
./bzip2/build_autojit/bzip2 --compress bzip2/outputs/test_autojit.txt

md5sum --check bzip2-test.md5
