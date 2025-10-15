#!/usr/bin/env bash
set -xeuo pipefail

# Parse arguments
build_opts=""
for arg in "$@"; do
  case $arg in
    --autojitd)
      # Spawn autojitd as subprocess
      build_opts="--static"
      export AUTOJITD_FORCE_DAEMON="On"
      ;;
    --autojitd=*)
      # Connect to running autojitd
      build_opts="--static"
      export AUTOJITD_FORCE_SPAWN="On"
      export AUTOJIT_DAEMON_PATH="${arg#--autojitd=}"
      ;;
  esac
done

echo "Test bzip2 with autojit"
rm -rf bzip2
rm -rf /tmp/autojit_*.ll
mkdir bzip2

export CCACHE_DISABLE=1
export AUTOJIT_DEBUG=1

./bzip2-autojit-setup.sh 2>&1 | tee bzip2/test-autojit-setup.log
./bzip2-autojit-build.sh "$build_opts" 2>&1 | tee bzip2/test-autojit-build.log
./bzip2/build_autojit/bzip2 --help 2>&1 | tee bzip2/test-autojit-run-help.log

mkdir -p bzip2/outputs
cp inputs/data1.txt bzip2/outputs/test_autojit.txt
./bzip2/build_autojit/bzip2 --compress bzip2/outputs/test_autojit.txt

md5sum --check bzip2-test.md5
