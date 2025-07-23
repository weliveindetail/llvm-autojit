## Work in progress

Everything is in a [Kraut und Rüben](https://www.linguee.de/deutsch-englisch/uebersetzung/wie+kraut+und+r%C3%BCben.html) state pretty much

## Build

Ubuntu 22.04 (x86_64):
```
> git clone https://github.com/llvm/llvm-project
> cd llvm-project
> git switch release/20.x
> git clone https://github.com/weliveindetail/llvm-autojit
> CC=clang-20 CXX=clang++-20 cmake -Sllvm -Bbuild -GNinja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=$(pwd)/build-install \
        -DLLVM_TARGETS_TO_BUILD="ARM;AArch64;X86" \
        -DLLVM_ENABLE_PROJECTS="clang;lld" \
        -DLLVM_ENABLE_RUNTIMES="compiler-rt" \
        -DLLVM_ENABLE_LIBCXX=On \
        -DLLVM_BUILD_LLVM_DYLIB=On \
        -DLLVM_LINK_LLVM_DYLIB=On \
        -DLLVM_USE_LINKER=lld \
        -DLLVM_EXTERNAL_PROJECTS=llvm-autojit \
        -DLLVM_EXTERNAL_LLVM_AUTOJIT_SOURCE_DIR=$(pwd)/llvm-autojit
> ninja -C build check-autojit
-- Testing: 5 tests, 5 workers --
PASS: AutoJIT :: debug.cpp (1 of 5)
PASS: AutoJIT :: extract.cpp (2 of 5)
PASS: AutoJIT :: runtime.cpp (3 of 5)
PASS: AutoJIT :: archives.cpp (4 of 5)
PASS: AutoJIT :: cus.cpp (5 of 5)

Testing Time: 8.84s

Total Discovered Tests: 5
  Passed: 5 (100.00%)
```

## Benchmark

For now compile-times are longer:
```
> ninja -C build install-autojit-bench
> cd build-install/benchmark
> ./setup.sh
Cloning into 'llvm-autojit-bench'...
remote: Enumerating objects: 45881, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 45881 (delta 0), reused 0 (delta 0), pack-reused 45876 (from 2)
Receiving objects: 100% (45881/45881), 126.97 MiB | 41.35 MiB/s, done.
Resolving deltas: 100% (12874/12874), done.
Updating files: 100% (55349/55349), done.

Setting up benchmark 401.bzip2
Building regular binary..
...
If you got this far and the "cmp"s didn't complain, it looks
like you're in business.
..
real  0m4,969s
user  0m4,561s
sys   0m0,380s

Building AutoJIT binary..
...
If you got this far and the "cmp"s didn't complain, it looks
like you're in business.
...
real  0m12,518s
user  0m11,822s
sys   0m0,407s
```

Run-times as well:
```
Generating test files..
Run-time regular:
real  0m0,803s
user  0m0,801s
sys   0m0,002s
Run-time autojit:
real  0m2,269s
user  0m2,205s
sys   0m0,020s

Run-time regular:
real  0m1,744s
user  0m1,735s
sys   0m0,009s
Run-time autojit:
real  0m3,567s
user  0m3,264s
sys   0m0,025s
```

## Expected log output

```
./$ time bzip2/build_autojit/bzip2 -1 bzip2/inputs/data1.txt
autojit-runtime: Registering module /tmp/autojit_2d1387ca92e7b83c7aa238c36b76c79a.bc
autojit-runtime: Registering module /tmp/autojit_2868f90adcbf0268b9c7bff1285a8ae9.bc
...
autojit-runtime: Scheduling module for materialization /tmp/autojit_2d1387ca92e7b83c7aa238c36b76c79a.bc (source: bzip2.c)
Promoting linkage for lazy function mySIGSEGVorSIGBUScatcher$llvm_autojit_module_2d1387ca92e7b83c7aa238c36b76c79a
...
Adding lazy function to JIT: fopen_output_safely$llvm_autojit_module_2d1387ca92e7b83c7aa238c36b76c79a
Adding lazy function to JIT: main$llvm_autojit_module_2d1387ca92e7b83c7aa238c36b76c79a
Adding lazy function to JIT: mySIGSEGVorSIGBUScatcher$llvm_autojit_module_2d1387ca92e7b83c7aa238c36b76c79a
...
libunwind: __unw_add_dynamic_fde: bad fde: FDE is really a CIE
autojit-runtime: Materialized function main from /tmp/autojit_2d1387ca92e7b83c7aa238c36b76c79a.bc at address 0x79960725d070
autojit-runtime: Function pointer patched at address 0x5f3af2e71bf8 with value 0x79960725d070

real    0m2,641s
user    0m2,352s
sys     0m0,039s
```
