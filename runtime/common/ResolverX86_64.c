/* Resolver for x86-64 trampolines. It's shared between the in-process runtime
 * and the static stub, which both define __llvm_autojit_materialize().
 *
 * A trampoline loads the address of its entry (see common/LazyModule.h) into
 * r11 and jumps through its slot. Until the function is materialized, the
 * slot points to a thunk that jumps here. We preserve all registers that may
 * carry arguments, including the vector state, materialize the function and
 * jump to it. Stack arguments stay untouched.
 */

#if defined(__x86_64__) && defined(__ELF__)

#include "common/LazyModule.h"

#include <cpuid.h>
#include <stdint.h>
#include <stdlib.h>

void *__llvm_autojit_materialize(void **Slot, uint64_t Guid,
                                 const void *Module);

/* Size of the XSAVE area for all enabled state components, or 0 if we have
 * to use FXSAVE */
__attribute__((visibility("hidden"))) uint32_t __llvm_autojit_xsave_size = 0;

/* For testing: clobber vector registers while materializing */
static int ClobberVectorRegs = 0;

__attribute__((constructor)) static void initXSaveSize(void) {
  const char *Clobber = getenv("AUTOJIT_TEST_CLOBBER_VECTOR_REGS");
  if (Clobber && *Clobber) {
    /* We might run before the constructor that initializes CPU features */
    __builtin_cpu_init();
    ClobberVectorRegs = __builtin_cpu_supports("avx");
  }

  unsigned eax, ebx, ecx, edx;
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx) || !(ecx & bit_OSXSAVE))
    return;
  if (!__get_cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx))
    return;
  /* EBX is the size for the features that are enabled in XCR0 */
  __llvm_autojit_xsave_size = ebx;
}

__attribute__((target("avx"))) static void clobberVectorRegs(void) {
  __asm__ volatile("vpcmpeqd %%ymm0, %%ymm0, %%ymm0\n"
                   "vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n"
                   "vpcmpeqd %%ymm2, %%ymm2, %%ymm2\n"
                   "vpcmpeqd %%ymm3, %%ymm3, %%ymm3\n"
                   "vpcmpeqd %%ymm4, %%ymm4, %%ymm4\n"
                   "vpcmpeqd %%ymm5, %%ymm5, %%ymm5\n"
                   "vpcmpeqd %%ymm6, %%ymm6, %%ymm6\n"
                   "vpcmpeqd %%ymm7, %%ymm7, %%ymm7\n" ::
                       : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
                         "xmm6", "xmm7");
}

__attribute__((visibility("hidden"))) void *
__llvm_autojit_resolve_entry(const autojit_trampoline_entry_t *Entry) {
  if (ClobberVectorRegs)
    clobberVectorRegs();
  /* The slot is writable, only the entry is const */
  void **Slot = (void **)((uintptr_t)Entry + Entry->slot_offset);
  const void *Module = (const char *)Entry + Entry->module_offset;
  return __llvm_autojit_materialize(Slot, Entry->guid, Module);
}

/* clang-format off */
__asm__(
  ".text\n"
  ".globl __llvm_autojit_resolve\n"
  ".type __llvm_autojit_resolve,@function\n"
  ".p2align 4\n"
  "__llvm_autojit_resolve:\n"
  "  .cfi_startproc\n"
  /* Indirect branch target for CET, a no-op otherwise */
  "  endbr64\n"
  "  pushq %rbp\n"
  "  .cfi_def_cfa_offset 16\n"
  "  .cfi_offset %rbp, -16\n"
  "  movq %rsp, %rbp\n"
  "  .cfi_def_cfa_register %rbp\n"
  /* Integer argument registers, rax for varargs, r10 for the static chain
   * and r11 with the entry */
  "  pushq %rax\n"
  "  pushq %rdi\n"
  "  pushq %rsi\n"
  "  pushq %rdx\n"
  "  pushq %rcx\n"
  "  pushq %r8\n"
  "  pushq %r9\n"
  "  pushq %r10\n"
  "  pushq %r11\n"
  /* Vector and x87 state */
  "  movl __llvm_autojit_xsave_size(%rip), %eax\n"
  "  testl %eax, %eax\n"
  "  jz 1f\n"
  "  subq %rax, %rsp\n"
  "  andq $-64, %rsp\n"
  /* XRSTOR requires the reserved bytes of the XSAVE header to be zero */
  "  movq $0, 512(%rsp)\n"
  "  movq $0, 520(%rsp)\n"
  "  movq $0, 528(%rsp)\n"
  "  movq $0, 536(%rsp)\n"
  "  movq $0, 544(%rsp)\n"
  "  movq $0, 552(%rsp)\n"
  "  movq $0, 560(%rsp)\n"
  "  movq $0, 568(%rsp)\n"
  "  movl $-1, %eax\n"
  "  movl $-1, %edx\n"
  "  xsave (%rsp)\n"
  "  jmp 2f\n"
  "1:\n"
  "  subq $512, %rsp\n"
  "  andq $-16, %rsp\n"
  "  fxsave64 (%rsp)\n"
  "2:\n"
  "  movq -72(%rbp), %rdi\n"
  "  call __llvm_autojit_resolve_entry\n"
  /* The target goes to r11 */
  "  movq %rax, -72(%rbp)\n"
  "  movl __llvm_autojit_xsave_size(%rip), %ecx\n"
  "  testl %ecx, %ecx\n"
  "  jz 3f\n"
  "  movl $-1, %eax\n"
  "  movl $-1, %edx\n"
  "  xrstor (%rsp)\n"
  "  jmp 4f\n"
  "3:\n"
  "  fxrstor64 (%rsp)\n"
  "4:\n"
  "  leaq -72(%rbp), %rsp\n"
  "  popq %r11\n"
  "  popq %r10\n"
  "  popq %r9\n"
  "  popq %r8\n"
  "  popq %rcx\n"
  "  popq %rdx\n"
  "  popq %rsi\n"
  "  popq %rdi\n"
  "  popq %rax\n"
  "  popq %rbp\n"
  "  .cfi_def_cfa %rsp, 8\n"
  "  jmpq *%r11\n"
  "  .cfi_endproc\n"
  ".size __llvm_autojit_resolve, .-__llvm_autojit_resolve\n"
);
/* clang-format on */

#endif
