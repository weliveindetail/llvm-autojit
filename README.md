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
        -DCMAKE_C_FLAGS="-Wno-unused-parameter" \
        -DCMAKE_INSTALL_PREFIX=$(pwd)/build-install \
        -DLLVM_TARGETS_TO_BUILD="ARM;AArch64;X86" \
        -DLLVM_ENABLE_PROJECTS="clang;lld" \
        -DLLVM_ENABLE_RUNTIMES="compiler-rt" \
        -DLLVM_ENABLE_LIBCXX=On \
        -DLLVM_BUILD_LLVM_DYLIB=On \
        -DLLVM_LINK_LLVM_DYLIB=On \
        -DLLVM_USE_LINKER=lld \
        -DLLVM_EXTERNAL_PROJECTS=llvm-autojit \
        -DLLVM_EXTERNAL_LLVM_AUTOJIT_SOURCE_DIR=$(pwd)/llvm-autojit \
        -DAUTOJIT_ENABLE_TPDE=On

> ninja -C build check-autojit
Running regression tests with TPDE: On
-- Testing: 9 tests, 9 workers --
PASS: AutoJIT :: debug-plugin.cpp (1 of 9)
PASS: AutoJIT :: extract.cpp (2 of 9)
PASS: AutoJIT :: debug-runtime.cpp (3 of 9)
PASS: AutoJIT :: tpde-cstdio.cpp (4 of 9)
PASS: AutoJIT :: runtime.cpp (5 of 9)
PASS: AutoJIT :: archives.cpp (6 of 9)
PASS: AutoJIT :: cus.cpp (7 of 9)
PASS: AutoJIT :: tpde-string.cpp (8 of 9)
XFAIL: AutoJIT :: tpde-format.cpp (9 of 9)

Testing Time: 35.21s

Total Discovered Tests: 9
  Passed           : 8 (88.89%)
  Expectedly Failed: 1 (11.11%)

> export AUTOJIT_USE_TPDE=Off
> ninja -C build check-autojit
Running regression tests with TPDE: Off
-- Testing: 9 tests, 9 workers --
PASS: AutoJIT :: extract.cpp (1 of 9)
PASS: AutoJIT :: debug-plugin.cpp (2 of 9)
PASS: AutoJIT :: tpde-cstdio.cpp (3 of 9)
PASS: AutoJIT :: debug-runtime.cpp (4 of 9)
PASS: AutoJIT :: runtime.cpp (5 of 9)
PASS: AutoJIT :: archives.cpp (6 of 9)
PASS: AutoJIT :: cus.cpp (7 of 9)
PASS: AutoJIT :: tpde-string.cpp (8 of 9)
XFAIL: AutoJIT :: tpde-format.cpp (9 of 9)

Testing Time: 35.43s

Total Discovered Tests: 9
  Passed           : 8 (88.89%)
  Expectedly Failed: 1 (11.11%)
```

## Build with TPDE

```
> git -C llvm-autojit submodule update --init --recursive
> git apply llvm-autojit/deps/tpde/llvm.616f2b685b06.patch
Applied patch to 'clang/include/clang/Basic/CodeGenOptions.def' cleanly.
Applied patch to 'clang/include/clang/Driver/Options.td' cleanly.
Applied patch to 'clang/lib/CodeGen/BackendUtil.cpp' cleanly.
Applied patch to 'clang/lib/CodeGen/CMakeLists.txt' cleanly.
Applied patch to 'clang/lib/Driver/ToolChains/Clang.cpp' cleanly.
Applied patch to 'clang/lib/Driver/ToolChains/Flang.cpp' cleanly.
Applied patch to 'flang/include/flang/Frontend/CodeGenOptions.def' cleanly.
Applied patch to 'flang/lib/Frontend/CMakeLists.txt' cleanly.
Applied patch to 'flang/lib/Frontend/CompilerInvocation.cpp' cleanly.
Applied patch to 'flang/lib/Frontend/FrontendActions.cpp' cleanly.
> ln -s $(pwd)/llvm-autojit/deps/tpde clang/lib/CodeGen/tpde2
> cmake -DAUTOJIT_ENABLE_TPDE=On build
```

## Benchmark

Clean `-O0 -g` debug builds of 401.bzip2 from spec2006-CPU on a single x86_64 Linux machine. Take it with a grain of salt.

Run benchmarks:
```
> ninja -C build install-autojit-bench
> cd build-install/benchmark
> ./setup.sh
Generating test files..
> $ ./run_all.sh
Benchmark 401.bzip2
Building regular binary..
  In 50 runs mean (min/max) time in seconds was: 3.871 (3.641 / 4.268)
Building AutoJIT binary..
  In 50 runs mean (min/max) time in seconds was: 3.564 (3.336 / 3.792)

AutoJIT cache file sizes:
  Static files: 0 kb
  Dynamic files: 514 kb

Run-time regular:
  In 3 runs mean (min/max) time in seconds was: 1.855 (1.761 / 1.999)
d41d8cd98f00b204e9800998ecf8427e  bzip2/outputs/data1_regular.txt
178b1561661d56c9bd4111d6b28adbc4  bzip2/outputs/data2_regular.txt

Run-time autojit:
  In 3 runs mean (min/max) time in seconds was: 4.009 (3.892 / 4.109)
d41d8cd98f00b204e9800998ecf8427e  bzip2/outputs/data1_autojit.txt
178b1561661d56c9bd4111d6b28adbc4  bzip2/outputs/data2_autojit.txt
```

## Runtime debug logs

```
> export AUTOJIT_DEBUG=On
> bzip2/build_autojit/bzip2 -1 inputs/data1.txt
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
```
