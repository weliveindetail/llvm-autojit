#!/bin/bash
set -e

echo "Benchmark 401.bzip2"
rm /tmp/autojit_*
rm -rf bzip2
mkdir bzip2

# Regular bench
echo "Compile-time regular:"
./meantime.py --setup bzip2-regular-setup.sh --runs 10 bzip2-regular-build.sh

# AutoJIT bench
echo "Compile-time AutoJIT:"
./meantime.py --setup bzip2-autojit-setup.sh --runs 10 bzip2-autojit-build.sh

echo ""
echo "Binary sizes:"
kb_regular=$(stat -c%s bzip2/build_regular/bzip2 | awk '{print int($1/1024)}')
kb_autojit=$(stat -c%s bzip2/build_autojit/bzip2 | awk '{print int($1/1024)}')
echo "  Regular: ${kb_regular} kb"
echo "  AutoJIT: ${kb_autojit} kb"

echo ""
bytes_lazy=$(find /tmp -name "autojit_[0-9a-f]*.*" ! -name "*_static.*"  ! -name "*_incoming.*" -exec stat -c%s {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
kb_lazy=$((bytes_lazy/1024))
echo "AutoJIT bitcode cache size: ${kb_lazy} kb"

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
