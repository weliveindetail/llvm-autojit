#!/usr/bin/env bash
set -xeo pipefail

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=On

# Default to shlib build
if [ -z "$AUTOJIT_BUILD_DIR" ]; then
  export AUTOJIT_LINK_STATIC_RUNTIME=Off
  export AUTOJIT_BUILD_DIR=build_autojit_shlib
fi

# Opt-in to static build with external autojitd for local testing
if [[ "$1" == "--autojitd" ]]; then
  export AUTOJITD_FORCE_SPAWN=Off
  export AUTOJITD_FORCE_DAEMON=On
  export AUTOJIT_LINK_STATIC_RUNTIME=On
  export AUTOJIT_BUILD_DIR=build_autojit_static
fi

echo "Test bzip2 with autojit"
rm -rf bzip2
rm -f /tmp/autojit_*
mkdir bzip2

./bzip2-autojit-setup.sh 2>&1 | tee bzip2/test-autojit-setup.log
./bzip2-autojit-build.sh 2>&1 | tee bzip2/test-autojit-build.log
./bzip2/$AUTOJIT_BUILD_DIR/bzip2 --help 2>&1 | tee bzip2/test-autojit-run-help.log

mkdir -p bzip2/outputs
cp inputs/data1.txt bzip2/outputs/test_autojit.txt
./bzip2/$AUTOJIT_BUILD_DIR/bzip2 --compress bzip2/outputs/test_autojit.txt

md5sum --check bzip2-test.md5
