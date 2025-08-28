#!/bin/bash
set -e

echo "Benchmark 401.bzip2"
mkdir bzip2

# Regular bench
echo "Building regular binary.."
./meantime.py --setup bzip2-regular-setup.sh --runs 20 bzip2-regular-build.sh

# AutoJIT bench
echo "Building AutoJIT binary.."
./meantime.py --setup bzip2-autojit-setup.sh --runs 20 bzip2-autojit-build.sh

echo ""
echo "AutoJIT cache file sizes:"
bytes_static=$(find /tmp -name "autojit_[0-9a-f]*_static.*" -exec stat -c%s {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
bytes_lazy=$(find /tmp -name "autojit_[0-9a-f]*.*" ! -name "*_static.*" -exec stat -c%s {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
kb_static=$((bytes_static/1024))
kb_lazy=$((bytes_lazy/1024))
echo "  Static files: ${kb_static} kb"
echo "  Dynamic files: ${kb_lazy} kb"

# Runtime bench
rm -rf bzip2/outputs
mkdir bzip2/outputs
echo ""
echo "Run-time regular:"
./meantime.py --runs 3 bzip2-regular-run.sh
md5sum bzip2/outputs/data1_regular.txt
md5sum bzip2/outputs/data2_regular.txt

echo ""
echo "Run-time autojit:"
./meantime.py --runs 3 bzip2-autojit-run.sh
md5sum bzip2/outputs/data1_autojit.txt
md5sum bzip2/outputs/data2_autojit.txt
