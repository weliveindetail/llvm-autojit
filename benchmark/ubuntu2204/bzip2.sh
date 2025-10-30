#!/bin/bash
set -eo pipefail

# Default to shlib build
export AUTOJIT_LINK_STATIC_RUNTIME=Off
export AUTOJIT_BUILD_DIR=build_autojit_shlib
repetitions=10
flavor="shlib"

# Parse arguments
build_opts=""
for arg in "$@"; do
  case $arg in
    --runs=*)
      repetitions="${arg#--runs=}"
      ;;
    --autojitd)
      # Opt-in to static build with external autojitd for local testing
      export AUTOJITD_FORCE_SPAWN=Off
      export AUTOJITD_FORCE_DAEMON=On
      export AUTOJIT_LINK_STATIC_RUNTIME=On
      export AUTOJIT_BUILD_DIR=build_autojit_static
      flavor="static"
      ;;
    *)
      echo "Invalid parameter: ${arg}"
      exit -1
      ;;
  esac
done

echo "Benchmark 401.bzip2 ($flavor) in $repetitions runs"
rm -rf bzip2

# Regular bench
echo "Compile-time regular:"
./meantime.py --setup bzip2-regular-setup.sh --runs $repetitions bzip2-regular-build.sh

# AutoJIT bench
echo "Compile-time AutoJIT:"
export AUTOJIT_BUILD_DIR=build_autojit
./meantime.py --setup bzip2-autojit-setup.sh --runs $repetitions bzip2-autojit-build.sh

echo ""
echo "Binary sizes:"
kb_regular=$(stat -c%s bzip2/build_regular/bzip2 | awk '{print int($1/1024)}')
kb_autojit=$(stat -c%s bzip2/build_autojit/bzip2 | awk '{print int($1/1024)}')
echo "  Regular: ${kb_regular} kb"
echo "  AutoJIT: ${kb_autojit} kb"

# FIXME: crashes the script
#echo ""
#bytes_lazy=$(find /tmp -name "autojit_*" 2>/dev/null | grep "\.bc$" | xargs stat -c%s | awk '{sum+=$1} END {print sum+0}')
#kb_lazy=$((bytes_lazy/1024))
#echo "AutoJIT bitcode cache size: ${kb_lazy} kb"

# Runtime bench
rm -rf bzip2/outputs
mkdir bzip2/outputs
echo ""
echo "Run-time regular:"
./meantime.py --runs 3 bzip2-regular-run.sh
md5sum bzip2/outputs/data1_regular.txt.bz2
md5sum bzip2/outputs/data2_regular.txt.bz2

echo ""
echo "Run-time AutoJIT:"
./meantime.py --runs 3 bzip2-autojit-run.sh
md5sum bzip2/outputs/data1_autojit.txt.bz2
md5sum bzip2/outputs/data2_autojit.txt.bz2

echo ""
echo ""
