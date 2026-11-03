// The in-process runtime must not resolve symbols from shared libraries that
// programs might define themselves: the executable would export its lazy
// definitions and they would interpose the ones in the shared library. Then the
// runtime would call lazy code while it materializes lazy code.
//
// RUN: %readelf -d %autojit_runtime_dir/libautojit-runtime.so | FileCheck %s
//
// CHECK-NOT: NEEDED{{.*}}libstdc++
// CHECK-NOT: NEEDED{{.*}}libc++
// CHECK-NOT: NEEDED{{.*}}libz.so
// CHECK-NOT: NEEDED{{.*}}libzstd
