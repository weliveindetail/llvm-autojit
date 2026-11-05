/* Resolver for AArch64 trampolines. It's shared between the in-process runtime
 * and the static stub, which both define __llvm_autojit_materialize().
 *
 * A trampoline loads the address of its entry (see common/LazyModule.h) into
 * x16 and jumps through its slot with x17. Until the function is materialized,
 * the slot points to a thunk that jumps here. x16 and x17 are the
 * intra-procedure-call scratch registers, so the caller doesn't expect them
 * to survive. We preserve all registers that may carry arguments,
 * materialize the function and jump to it. Stack arguments stay untouched.
 */

#if defined(__aarch64__) && defined(__ELF__)

#include "common/LazyModule.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void *__llvm_autojit_materialize(void **Slot, uint64_t Guid,
                                 const void *Module);

/* For testing: clobber vector registers while materializing */
static int ClobberVectorRegs = 0;

__attribute__((constructor)) static void initClobberVectorRegs(void) {
  const char *Clobber = getenv("AUTOJIT_TEST_CLOBBER_VECTOR_REGS");
  ClobberVectorRegs = Clobber && *Clobber;
}

static void clobberVectorRegs(void) {
  __asm__ volatile("movi v0.2d, #0xffffffffffffffff\n"
                   "movi v1.2d, #0xffffffffffffffff\n"
                   "movi v2.2d, #0xffffffffffffffff\n"
                   "movi v3.2d, #0xffffffffffffffff\n"
                   "movi v4.2d, #0xffffffffffffffff\n"
                   "movi v5.2d, #0xffffffffffffffff\n"
                   "movi v6.2d, #0xffffffffffffffff\n"
                   "movi v7.2d, #0xffffffffffffffff\n" ::
                       : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7");
}

__attribute__((visibility("hidden"))) void *
__llvm_autojit_resolve_entry(const autojit_trampoline_entry_t *Entry) {
  if (ClobberVectorRegs)
    clobberVectorRegs();
  /* The entry follows the instructions of the trampoline */
  autojit_trampoline_entry_t E;
  memcpy(&E, Entry, sizeof(E));
  /* The slot is writable, only the entry is const */
  void **Slot = (void **)((uintptr_t)Entry + E.slot_offset);
  const void *Module = (const char *)Entry + E.module_offset;
  return __llvm_autojit_materialize(Slot, E.guid, Module);
}

/* Frame layout (240 bytes):
 *     0  x29, x30  frame record
 *    16  x0 - x7   integer arguments
 *    80  x8, x15   indirect result, static chain (LLVM)
 *    96  x18       static chain (GCC), platform register
 *   112  q0 - q7   floating-point and vector arguments
 */
/* clang-format off */
__asm__(
  ".text\n"
  ".globl __llvm_autojit_resolve\n"
  ".type __llvm_autojit_resolve,%function\n"
  ".p2align 4\n"
  "__llvm_autojit_resolve:\n"
  "  .cfi_startproc\n"
  /* Landing pad for BTI, a no-op otherwise. Valid for br x17. */
  "  hint #34\n"
  "  stp x29, x30, [sp, #-240]!\n"
  "  .cfi_def_cfa_offset 240\n"
  "  .cfi_offset x29, -240\n"
  "  .cfi_offset x30, -232\n"
  "  mov x29, sp\n"
  "  .cfi_def_cfa x29, 240\n"
  "  stp x0, x1, [sp, #16]\n"
  "  stp x2, x3, [sp, #32]\n"
  "  stp x4, x5, [sp, #48]\n"
  "  stp x6, x7, [sp, #64]\n"
  "  stp x8, x15, [sp, #80]\n"
  "  str x18, [sp, #96]\n"
  "  stp q0, q1, [sp, #112]\n"
  "  stp q2, q3, [sp, #144]\n"
  "  stp q4, q5, [sp, #176]\n"
  "  stp q6, q7, [sp, #208]\n"
  "  mov x0, x16\n"
  "  bl __llvm_autojit_resolve_entry\n"
  "  mov x16, x0\n"
  "  ldp q6, q7, [sp, #208]\n"
  "  ldp q4, q5, [sp, #176]\n"
  "  ldp q2, q3, [sp, #144]\n"
  "  ldp q0, q1, [sp, #112]\n"
  "  ldr x18, [sp, #96]\n"
  "  ldp x8, x15, [sp, #80]\n"
  "  ldp x6, x7, [sp, #64]\n"
  "  ldp x4, x5, [sp, #48]\n"
  "  ldp x2, x3, [sp, #32]\n"
  "  ldp x0, x1, [sp, #16]\n"
  "  ldp x29, x30, [sp], #240\n"
  "  .cfi_def_cfa sp, 0\n"
  "  .cfi_restore x29\n"
  "  .cfi_restore x30\n"
  "  br x16\n"
  "  .cfi_endproc\n"
  ".size __llvm_autojit_resolve, .-__llvm_autojit_resolve\n"
);
/* clang-format on */

#endif
