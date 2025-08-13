#!/bin/bash
set -e

echo "Benchmark 401.bzip2"
mkdir bzip2

# Regular bench
echo "Building regular binary.."
./timeavg.py --setup bzip2-regular-setup.sh --runs 20 bzip2-regular-build.sh

# AutoJIT bench
echo "Building AutoJIT binary.."
./timeavg.py --setup bzip2-autojit-setup.sh --runs 20 bzip2-autojit-build.sh

# Runtime bench
rm -rf bzip2/outputs
mkdir bzip2/outputs
echo ""
echo "Run-time regular:"
./timeavg.py --runs 3 bzip2-regular-run.sh
md5sum bzip2/outputs/data1_regular.txt
md5sum bzip2/outputs/data2_regular.txt

echo ""
echo "Run-time autojit:"
./timeavg.py --runs 3 bzip2-autojit-run.sh
md5sum bzip2/outputs/data1_autojit.txt
md5sum bzip2/outputs/data2_autojit.txt
