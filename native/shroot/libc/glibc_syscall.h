#ifdef __ASSEMBLER__
# if IS_IN (libc)
#  define SHROOT_DO_SYSCALL \
    adrp x9, __shroot_entry; \
    ldr x9, [x9, :lo12:__shroot_entry]; \
    cbz x9, 991f; \
    ldr w10, [x9, #24]; \
    cmp x8, x10; \
    b.hs 991f; \
    ldr x9, [x9, #16]; \
    ldrb w10, [x9, x8]; \
    tbz w10, #0, 991f; \
    stp x29, x30, [sp, #-16]!; \
    cfi_adjust_cfa_offset (16); \
    cfi_rel_offset (x29, 0); \
    cfi_rel_offset (x30, 8); \
    bl __shroot_syscall_asm; \
    ldp x29, x30, [sp], #16; \
    cfi_restore (x29); \
    cfi_restore (x30); \
    cfi_adjust_cfa_offset (-16); \
    b 992f; \
991: svc 0; \
992:
# else
#  define SHROOT_DO_SYSCALL svc 0
# endif
#else
# if IS_IN (libc) && !defined SHROOT_RAW_SYSCALLS
#  include <cooperative_entry.h>
extern const struct md_entry_api *__shroot_entry attribute_hidden;
extern long __shroot_syscall (long, const uint64_t *) attribute_hidden;
extern int __shroot_cp_try (long, const uint64_t *, long *) attribute_hidden;
#  define SHROOT_ARGS_0() {0}
#  define SHROOT_ARGS_1(a0) {(uint64_t) (a0)}
#  define SHROOT_ARGS_2(a0, a1) {(uint64_t) (a0), (uint64_t) (a1)}
#  define SHROOT_ARGS_3(a0, a1, a2) {(uint64_t) (a0), (uint64_t) (a1), (uint64_t) (a2)}
#  define SHROOT_ARGS_4(a0, a1, a2, a3) {(uint64_t) (a0), (uint64_t) (a1), (uint64_t) (a2), (uint64_t) (a3)}
#  define SHROOT_ARGS_5(a0, a1, a2, a3, a4) {(uint64_t) (a0), (uint64_t) (a1), (uint64_t) (a2), (uint64_t) (a3), (uint64_t) (a4)}
#  define SHROOT_ARGS_6(a0, a1, a2, a3, a4, a5) {(uint64_t) (a0), (uint64_t) (a1), (uint64_t) (a2), (uint64_t) (a3), (uint64_t) (a4), (uint64_t) (a5)}
#  define INTERNAL_SYSCALL_RAW(name, nr, args...) \
  ({ long _shroot_nr = (name), _shroot_result; \
     if (md_entry_offered (__shroot_entry, _shroot_nr, MD_ENTRY_ORDINARY)) \
       { const uint64_t _shroot_args[6] = SHROOT_ARGS_##nr(args); \
         _shroot_result = __shroot_syscall (_shroot_nr, _shroot_args); } \
     else _shroot_result = SHROOT_KERNEL_SYSCALL_RAW (_shroot_nr, nr, args); \
     _shroot_result; })
# else
#  define INTERNAL_SYSCALL_RAW(name, nr, args...) SHROOT_KERNEL_SYSCALL_RAW(name, nr, args)
# endif
#endif
