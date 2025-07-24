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

Run benchmarks:
```
> ninja -C build install-autojit-bench
> cd build-install/benchmark
> ./setup.sh
Cloning into 'llvm-autojit-bench'...
...
Setting up benchmark 401.bzip2
Building regular binary..
...
real  0m4,969s
user  0m4,561s
sys   0m0,380s

Building AutoJIT binary..
...
real  0m12,518s
user  0m11,822s
sys   0m0,407s

Run-time regular:
0m0,946s f5de26e14d257254235039aabd5ec18c
...

Run-time autojit:
0m0,997s f5de26e14d257254235039aabd5ec18c
...
```

## Early-stage results

Debug builds of 401.bzip2 from spec2006-CPU (`-O0 -g`) and small sample sizes (~10 repetitions) on a single x86_64 Linux machine. Take it with a grain of salt.

### Compile-time

No compile-time gains in release build of autojit plugin and runtime in LLVM/clang 20:
```
regular autojit
 0.729s  0.515s
 0.622s  0.490s
 0.489s  0.731s
 0.500s  1.115s
 0.568s  0.730s
 0.839s  0.651s
 ------  ------
  0.62s   0.70s  -->  0.89x speedup
```

Using a debug-toolchain, we do see a small speedup:
```
regular autojit
 4.155s  3.557s
 4.041s  3.645s
 ------  ------
 4.098s  3.601s  -->  1.14x speedup
```

### Run-time

autojit using the native LLVM backend:
```
regular autojit speedup abs = rel   hash
  0.95s   1.11s    -0.16s = 0.86x	  f5de26e14d257254235039aabd5ec18c
  1.79s   1.98s    -0.19s = 0.90x   11c2d00a1ab55557475a16746baa9af7
```

autojit using TPDE:
```
regular autojit speedup abs = rel   hash
  0.97s   0.97s        0s = 1.00x	  f5de26e14d257254235039aabd5ec18c
  1.79s   1.78s    -0.01s = 0.99x   11c2d00a1ab55557475a16746baa9af7
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
