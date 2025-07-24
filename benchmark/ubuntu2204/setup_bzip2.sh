#!/bin/bash
set -e

SPEC_CPU2006="$1"

echo "Setting up benchmark 401.bzip2"
mkdir bzip2 && cd bzip2

# Regular bench
echo "Building regular binary.."
cp -r $SPEC_CPU2006/original/401.bzip2/bzip2-1.0.3 build_regular
cd build_regular
make clean
time make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
cd ..

# AutoJIT bench
echo "Building AutoJIT binary.."
cp -r $SPEC_CPU2006/original/401.bzip2/bzip2-1.0.3 build_autojit
cd build_autojit
make clean
time make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS -fpass-plugin=$AUTOJIT_PLUGIN" LDFLAGS="$LDFLAGS -Wl,-rpath=$AUTOJIT_RUNTIME_DIR -Wl,--no-gc-sections -L$AUTOJIT_RUNTIME_DIR -lautojit-runtime -rdynamic"
cd ..

# Runtime bench
rm -rf outputs
mkdir outputs
echo ""
echo "Run-time regular:"
for i in {1..2}; do
    for _ in {1..10}; do
        duration=$({ time build_regular/bzip2 -1 ../inputs/data${i}.txt --stdout > outputs/data${i}_regular.txt 2>/dev/null; } 2>&1 | grep real | awk '{print $2}')
        hash=$(md5sum outputs/data${i}_regular.txt | awk '{print $1}')
        echo "$duration $hash"
    done
done
echo ""
echo "Run-time autojit:"
for i in {1..2}; do
    for _ in {1..10}; do
        duration=$({ time build_autojit/bzip2 -1 ../inputs/data${i}.txt --stdout > outputs/data${i}_autojit.txt 2>/dev/null; } 2>&1 | grep real | awk '{print $2}')
        hash=$(md5sum outputs/data${i}_autojit.txt | awk '{print $1}')
        echo "$duration $hash"
    done
done
