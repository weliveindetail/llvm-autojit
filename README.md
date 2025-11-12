# llvm-autojit plugin

Be lazy and compile your code at runtime. This project develops a compiler
plugin that outlines function definitons to disk and a runtime library that
compiles them on-demand. For now please consider it a case study. It works for
simple exmaples on Linux, but it's not at all ready for production.

## Unified Build

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
        -DLLVM_BUILD_LLVM_DYLIB=On \
        -DLLVM_LINK_LLVM_DYLIB=On \
        -DLLVM_USE_LINKER=lld \
        -DLLVM_EXTERNAL_PROJECTS=llvm-autojit \
        -DLLVM_EXTERNAL_LLVM_AUTOJIT_SOURCE_DIR=$(pwd)/llvm-autojit \
        -DAUTOJIT_EMBED_ORC_RUNTIME=On \
        -DAUTOJIT_ENABLE_TPDE=On

> ninja -C runtimes/runtimes-bins compiler-rt/lib/orc/all
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
variable `AUTOJIT_DEBUG=On` is set. The runtime enable debug logging from LLVM's
`orc` category as well, if LLVM build mode is `Debug`.

## Record RPC traffic between stub and autojitd

We run the daemon unmodified and remember the socket path:
```
> ./autojitd
[autojit-runtime] Daemon process 49574 runs in standalone mode on socket: /run/user/1000/autojitd.sock
[autojit-runtime] Waiting for connection...
```

We use `socat` to forward it to auxiliary socket `autojitd-trace` and record the traffic in both ways as binary blobs:
```
> socat -r socat-stub.bin -R socat-autojitd.bin \
    UNIX-LISTEN:/run/user/1000/autojitd-trace.sock,fork \
    UNIX-CONNECT:/run/user/1000/autojitd.sock
```

Now we find the program that we want to record RPC traffic for. It must link the autojit stub statically and we must point it to the auxiliary socket:
```
> AUTOJIT_SOCKET_PATH=/run/user/1000/autojitd-trace.sock build/test/Output/daemon.c.tmp.exe
AutoJIT Daemon Test
add(1, 4) = 5
factorial(5) = 120
Test completed successfully
```

Once it terminated, we find the recorded RPC traffic in the binary files. `socat-stub.bin` contains the bytes sent from the stub:
```
> hexdump -C build/socat-stub.bin
00000000  82 04 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020  18 00 00 00 00 00 00 00  78 38 36 5f 36 34 2d 75  |........x86_64-u|
00000030  6e 6b 6e 6f 77 6e 2d 6c  69 6e 75 78 2d 67 6e 75  |nknown-linux-gnu|
00000040  00 10 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 00 00  11 00 00 00 00 00 00 00  |................|
00000060  27 00 00 00 00 00 00 00  5f 5f 6c 6c 76 6d 5f 6f  |'.......__llvm_o|
00000070  72 63 5f 53 69 6d 70 6c  65 52 65 6d 6f 74 65 45  |rc_SimpleRemoteE|
00000080  50 43 5f 64 69 73 70 61  74 63 68 5f 63 74 78 e0  |PC_dispatch_ctx.|
00000090  04 ff 1e 75 55 00 00 26  00 00 00 00 00 00 00 5f  |...uU..&......._|
000000a0  5f 6c 6c 76 6d 5f 6f 72  63 5f 53 69 6d 70 6c 65  |_llvm_orc_Simple|
000000b0  52 65 6d 6f 74 65 45 50  43 5f 64 69 73 70 61 74  |RemoteEPC_dispat|
...
```

`socat-autojitd.bin` contains the bytes sent from autojitd:
```
$ hexdump -C build/socat-autojitd.bin
00000000  38 00 00 00 00 00 00 00  03 00 00 00 00 00 00 00  |8...............|
00000010  01 00 00 00 00 00 00 00  d0 06 65 1e 75 55 00 00  |..........e.uU..|
00000020  00 05 ff 1e 75 55 00 00  00 00 00 00 00 00 00 00  |....uU..........|
00000030  00 00 00 00 00 00 00 00  a3 00 00 00 00 00 00 00  |................|
00000040  00 00 00 00 00 00 00 00  02 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 00 00 00  18 00 00 00 00 00 00 00  |................|
00000060  78 38 36 5f 36 34 2d 75  6e 6b 6e 6f 77 6e 2d 6c  |x86_64-unknown-l|
00000070  69 6e 75 78 2d 67 6e 75  00 10 00 00 00 00 00 00  |inux-gnu........|
00000080  00 00 00 00 00 00 00 00  02 00 00 00 00 00 00 00  |................|
00000090  14 00 00 00 00 00 00 00  61 75 74 6f 6a 69 74 5f  |........autojit_|
000000a0  72 70 63 5f 72 65 67 69  73 74 65 72 80 5b 6f f9  |rpc_register.[o.|
000000b0  17 63 00 00 17 00 00 00  00 00 00 00 61 75 74 6f  |.c..........auto|
...
```
