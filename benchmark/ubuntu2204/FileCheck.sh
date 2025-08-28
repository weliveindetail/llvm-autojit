#!/usr/bin/env bash
set -e

echo "Benchmark FileCheck"
rm -rf /tmp/autojit_*
mkdir FileCheck

# Regular bench
echo "Building regular binary.."
./meantime.py --setup FileCheck-regular-setup.sh --runs 3 FileCheck-regular-build.sh

# AutoJIT bench
echo "Building AutoJIT binary.."
./meantime.py --setup FileCheck-autojit-setup.sh --runs 3 FileCheck-autojit-build.sh

echo ""
echo "AutoJIT cache file sizes:"
bytes_static=$(find /tmp -name "autojit_[0-9a-f]*_static.*" -exec stat -c%s {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
bytes_lazy=$(find /tmp -name "autojit_[0-9a-f]*.*" ! -name "*_static.*" -exec stat -c%s {} + 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
kb_static=$((bytes_static/1024))
kb_lazy=$((bytes_lazy/1024))
echo "  Static files: ${kb_static} kb"
echo "  Dynamic files: ${kb_lazy} kb"

# Runtime bench
echo ""
echo "Run-time regular:"
./meantime.py --runs 3 FileCheck-regular-run.sh

echo ""
echo "Run-time autojit:"
./meantime.py --runs 3 FileCheck-autojit-run.sh

echo ""
echo ""
