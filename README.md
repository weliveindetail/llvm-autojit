# llvm-autojit plugin

Be lazy and compile your code at runtime. This project develops a compiler
plugin that outlines function definitons to disk and a runtime library that
compiles them on-demand. For now please consider it a case study. It works for
simple exmaples on Linux, but it's not at all ready for production.

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
        -DAUTOJIT_ENABLE_ORC_RUNTIME=On \
        -DAUTOJIT_ENABLE_TPDE=On

> ninja -C build check-autojit
Running regression tests with TPDE: On
-- Testing: 12 tests, 12 workers --
PASS: AutoJIT :: opt.ll (1 of 12)
PASS: AutoJIT :: skip.cpp (2 of 12)
PASS: AutoJIT :: extract.cpp (3 of 12)
PASS: AutoJIT :: debug-plugin.cpp (4 of 12)
PASS: AutoJIT :: gvs.cpp (5 of 12)
PASS: AutoJIT :: debug-runtime.cpp (6 of 12)
PASS: AutoJIT :: fnptr.cpp (7 of 12)
PASS: AutoJIT :: exceptions.cpp (8 of 12)
PASS: AutoJIT :: runtime.cpp (9 of 12)
PASS: AutoJIT :: archives.cpp (10 of 12)
PASS: AutoJIT :: cus.cpp (11 of 12)
PASS: AutoJIT :: libcxx.cpp (12 of 12)

Testing Time: 14.19s

Total Discovered Tests: 12
  Passed: 12 (100.00%)
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

Test bzip2 with a AutoJIT debug build:
```
> ninja -C build install-autojit-bench
> cd build-install/benchmark && ./bzip2-test.sh
Test bzip2 with autojit
Configure: bzip2/test-autojit-setup.log
Build: bzip2/test-autojit-build.log
Run: bzip2/test-autojit-run.log
```

Run benchmark with a AutoJIT release build:
```
> ninja -C build-release install-autojit-bench
> cd build-install/benchmark
> ./setup.sh
Fetching benchmark code..
$ ./bzip2.sh
Benchmark 401.bzip2
Compile-time regular:
  In 10 runs mean (min/max) time in seconds was: 0.807 (0.555 / 1.078)
Compile-time AutoJIT:
  In 10 runs mean (min/max) time in seconds was: 0.723 (0.453 / 1.124)

Binary sizes:
  Regular: 182 kb
  AutoJIT: 35 kb

AutoJIT bitcode cache size: 385 kb

Run-time regular:
  In 3 runs mean (min/max) time in seconds was: 2.586 (2.434 / 2.782)
323c74b2d7815a0b22979f45a93323e0  bzip2/outputs/data1_regular.txt.bz2
c3c5e912092b78a8a53faa34e9d7494e  bzip2/outputs/data2_regular.txt.bz2

Run-time AutoJIT:
  In 3 runs mean (min/max) time in seconds was: 2.829 (2.612 / 3.012)
323c74b2d7815a0b22979f45a93323e0  bzip2/outputs/data1_autojit.txt.bz2
c3c5e912092b78a8a53faa34e9d7494e  bzip2/outputs/data2_autojit.txt.bz2
```

## Debugging

Both, plugin and the runtime dump all available debug info if environment
variable is set `AUTOJIT_DEBUG=On`

For usage see:
* [benchmark/ubuntu2204/bzip2-test.sh](benchmark/ubuntu2204/bzip2-test.sh)
* [test/debug-plugin.cpp](test/debug-plugin.cpp)
* [test/debug-runtime.cpp](test/debug-runtime.cpp)

For sample output see:
* [docs/sample-logs/bzip2-test-build.log](docs/sample-logs/bzip2-test-build.log)
* [docs/sample-logs/bzip2-test-run.log](docs/sample-logs/bzip2-test-run.log)
