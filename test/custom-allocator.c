// A program with its own allocator: the runtime calls it while it materializes
// lazy code, so its helpers must not be lazy either.
//
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -Wl,-rpath=%autojit_runtime_dir -lautojit-runtime -o %t_inprocess.exe
// RUN: %t_inprocess.exe | FileCheck %s
// RUN: %clang_c -fpass-plugin=%autojit_plugin %s -L%autojit_runtime_dir -lautojit_static_ldscript %fsanitize -o %t_remote.exe
// RUN: %t_remote.exe | FileCheck %s
//
// CHECK: allocated: ok

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static char Arena[1 << 28];
static size_t Offset;

size_t roundUp(size_t N) { return (N + 15) & ~(size_t)15; }

void *allocate(size_t N) {
  N = roundUp(N + 16);
  size_t Old = __atomic_fetch_add(&Offset, N, __ATOMIC_RELAXED);
  *(size_t *)(Arena + Old) = N - 16;
  return Arena + Old + 16;
}

void *malloc(size_t N) { return allocate(N); }
void free(void *P) {}

void *calloc(size_t A, size_t B) {
  void *P = allocate(A * B);
  memset(P, 0, A * B);
  return P;
}

void *realloc(void *P, size_t N) {
  void *Q = allocate(N);
  if (P) {
    size_t Old = ((size_t *)P)[-2];
    memcpy(Q, P, Old < N ? Old : N);
  }
  return Q;
}

void *aligned_alloc(size_t A, size_t N) {
  char *P = allocate(N + A);
  return (void *)(((size_t)P + A - 1) & ~(A - 1));
}

int posix_memalign(void **R, size_t A, size_t N) {
  *R = aligned_alloc(A, N);
  return 0;
}

void *memalign(size_t A, size_t N) { return aligned_alloc(A, N); }

int main(void) {
  char *P = malloc(8);
  strcpy(P, "ok");
  printf("allocated: %s\n", P);
  return 0;
}
