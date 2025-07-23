#!/bin/bash
set -e

SPEC_CPU2006="$1"

echo "Setting up benchmark 401.bzip2"
mkdir bzip2 && cd bzip2

# Regular build
echo "Building regular binary.."
cp -r $SPEC_CPU2006/original/401.bzip2/bzip2-1.0.3 build_regular
cd build_regular
make clean
time make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
cd ..

# AutoJIT build
echo "Building AutoJIT binary.."
cp -r $SPEC_CPU2006/original/401.bzip2/bzip2-1.0.3 build_autojit
cd build_autojit
make clean
time make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS -fpass-plugin=$AUTOJIT_PLUGIN" LDFLAGS="$LDFLAGS -Wl,-rpath=$AUTOJIT_RUNTIME_DIR -Wl,--no-gc-sections -L$AUTOJIT_RUNTIME_DIR -lautojit-runtime -rdynamic"
cd ..

echo "Generating test files.."
mkdir inputs
# Up to 10MB
for i in {1..2}; do
    head -c $((1024 * 1024 * 5 * i)) /dev/urandom | base64 > inputs/data${i}.txt
done

rm -rf outputs
mkdir outputs
echo "Run-time regular:"
for i in {1..2}; do
    time build_regular/bzip2 -1 inputs/data${i}.txt --stdout > outputs/data${i}_regular.txt
done
echo "Run-time autojit:"
for i in {1..2}; do
    time build_autojit/bzip2 -1 inputs/data${i}.txt --stdout > outputs/data${i}_autojit.txt
done
