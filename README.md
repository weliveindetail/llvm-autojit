# llvm-autojit plugin

Be lazy and compile your code at runtime. This project develops a compiler plugin that outlines function definitons to disk and a runtime library that compiles them on-demand.

## Status

Development reached a proof-of-concept state, where simple C, C++ and Rust programs build and run successfully. There is still a long way to go before this is ready for production. So far the only supported platform is x86-64 Ubuntu 22.04.

[![Ubuntu 22.04](https://github.com/weliveindetail/llvm-autojit/actions/workflows/ubuntu2204.yml/badge.svg)](https://github.com/weliveindetail/llvm-autojit/actions/workflows/ubuntu2204.yml)

## Install

Download a [release package](https://github.com/weliveindetail/llvm-autojit/releases) and:
```
> tar -C /usr/local  -xzvf llvm-autojit-21_v0.1_x86-64.tar.gz
./
./bin/
./bin/autojitd
./lib/
./lib/libautojit_static-x86_64.a
./lib/libautojit-runtime.so.21.1
./lib/autojit.so
./lib/libautojit-runtime.so

> which autojitd
/usr/local/bin/autojitd
```

## Basic C/C++ example

Create a `hello.c` with a simple hello world:
```c
#include "stdio.h"

int main(void) {
  printf("Hello C\n");
  return 0;
}
```

Install a llvm-autojit release along with [clang release 21](https://weliveindetail.github.io/blog/post/2021/05/28/debian-llvm-quick-install.html) and compile a debug version with the following commands. They load the plugin `autojit.so` in the compiler (absolute path is required) and pass the runtime `libautojit-runtime.so` as a shared library to the linker. We need to add `/usr/local/lib` as shared library search path and specify `-rdynamic` for the runtime to resolve dynamic symbols from the executable.
```
> clang-21 -O0 -g -fpass-plugin=/usr/local/lib/autojit.so -o hello.o -c hello.c
> clang-21 -Wl,-rpath=/usr/local/lib -lautojit-runtime -rdynamic -o hello_c_shlib hello.o
./hello_c_shlib
[autojit-runtime] Loading module from cache /tmp/autojit_2045016cb90d1e65d71c2407a2570927.o (source: hello.c)
Hello C
```

A shared library is a simple, but not always a practical way to provide our runtime. That's why we have another option: We can statically link a RPC stub that forwards all compile requests to `autojitd`. Mind the order of inputs (`autojit_static-x86-64` last) on the link line.
```
> clang-21 -O0 -g -fpass-plugin=/usr/local/lib/autojit.so -o hello.o -c hello.c
> clang-21 hello.o -lautojit_static-x86-64 -rdynamic -o hello_c_autojitd
> ./hello_c_autojitd
[autojit-runtime] Cannot install orc-runtime: missing C++ stdlib
[autojit-runtime] Loading module from cache /tmp/autojit_2045016cb90d1e65d71c2407a2570927.o (source: hello.c)
Hello C
[autojit-runtime] Warning: ignore RPC invocation after disconnect
```

In this case the stub spawned `autojitd` in a child process. Alternatively, it can run as a complete separate process in the background and handle all compile requests system-wide.

## Basic Rust example

LLVM plugins are not yet enabled in Rust release versions, but we can use a nightly version. The current plugin releases are tested with Rust nightly 1.91. Other versions may work as well. Please find more details in the [Dockerfile for our CI image](https://github.com/weliveindetail/llvm-autojit/blob/main/benchmark/ubuntu2204/llvm21/Dockerfile).
```
> rustc --version --verbose
rustc 1.91.0-nightly (1ebbd87a6 2025-08-11)
binary: rustc
commit-hash: 1ebbd87a62ce96a72b22da61b7c2c43893534842
commit-date: 2025-08-11
host: x86_64-unknown-linux-gnu
release: 1.91.0-nightly
LLVM version: 21.1.0
```

Once we have that, we create a `hello.rs` with a simple hello world:
```rs
fn main() {
  println!("Hello World!");
}
```

Compile and link in one step, then run the example:
```
> rustc -Z llvm-plugins="/usr/local/lib/autojit.so" \
        -L /usr/local/lib -lautojit-runtime
        -C link-arg=-Wl,-rpath,/usr/local/lib
        -C link-arg=-rdynamic
        -o hello_rust_shlib hello.rs
> ./hello_rust_shlib
[autojit-runtime] Loading module from cache /tmp/autojit_3c6eb49c3a3854d19574caf91dc7a72b.o (source: hello.984f8e64244731dd-cgu.0)
Hello World!
```

And here again, the shared library approach works, but might not be the best solution. Remember it's written in C++! Rustaceans might prefer to keep it in the separate `autojitd` process 🤓
```
> rustc -Z llvm-plugins="/usr/local/lib/autojit.so" \
        -L /usr/local/lib -lautojit_static-x86_64
        -C link-arg=-rdynamic
        -o hello_rust_autojitd hello.rs
./hello_rust_autojitd
[autojit-runtime] Cannot install orc-runtime: missing C++ stdlib
[autojit-runtime] Loading module from cache /tmp/autojit_3c6eb49c3a3854d19574caf91dc7a72b.o (source: hello.984f8e64244731dd-cgu.0)
Hello World!
[autojit-runtime] Warning: ignore RPC invocation after disconnect
```

## Benchmark

Clean `-O0 -g` debug builds of 401.bzip2 from spec2006-CPU on a single x86_64 Linux machine. Take it with a grain of salt.

Build the plugin against your installed LLVM release 21 and test the sample code:
```
> git clone https://github.com/weliveindetail/llvm-autojit
> CC=clang-21 CXX=clang++-21 cmake \
        -GNinja -Sllvm-autojit -Bbuild-external \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=$(pwd)/build-external/install
> ninja -C build-external install-autojit-bench
> cd build-external/install/benchmark
> ./setup.sh
Fetching benchmark code..
. ln -s /usr/lib/llvm-21/bin/clang /usr/local/bin/.
> ./bzip2-test.sh
Test bzip2 with autojit
...
+ md5sum --check bzip2-test.md5
bzip2/outputs/test_autojit.txt.bz2: OK
```

Run benchmark:
```
> $ ./bzip2.sh --runs=10
Benchmark 401.bzip2 (shlib) in 10 runs
Compile-time regular:
  In 10 runs mean (min/max) time in seconds was: 0.944 (0.708 / 1.235)
Compile-time AutoJIT:
  In 10 runs mean (min/max) time in seconds was: 0.744 (0.537 / 1.018)

Binary sizes:
  Regular: 189 kb
  AutoJIT: 42 kb

Run-time regular:
  In 3 runs mean (min/max) time in seconds was: 2.611 (2.485 / 2.760)
323c74b2d7815a0b22979f45a93323e0  bzip2/outputs/data1_regular.txt.bz2
c3c5e912092b78a8a53faa34e9d7494e  bzip2/outputs/data2_regular.txt.bz2

Run-time AutoJIT:
  In 3 runs mean (min/max) time in seconds was: 2.745 (2.604 / 2.889)
323c74b2d7815a0b22979f45a93323e0  bzip2/outputs/data1_autojit.txt.bz2
c3c5e912092b78a8a53faa34e9d7494e  bzip2/outputs/data2_autojit.txt.bz2
```

## Development

Please find documentation in [docs/develop.md](docs/develop.md)
