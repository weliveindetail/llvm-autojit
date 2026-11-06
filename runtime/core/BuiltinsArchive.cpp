// Compiler builtins for JITed code, see AutoJIT::initialize()
__asm__(".section .rodata\n"
        ".balign 8\n"
        ".global autojit_builtins_start\n"
        ".hidden autojit_builtins_start\n"
        "autojit_builtins_start:\n"
        ".incbin \"" AUTOJIT_BUILTINS_ARCHIVE "\"\n"
        ".global autojit_builtins_end\n"
        ".hidden autojit_builtins_end\n"
        "autojit_builtins_end:\n"
        ".previous\n");
