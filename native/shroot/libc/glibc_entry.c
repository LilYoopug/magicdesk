/* Guest glibc source integration, never loaded into Android's libc or ART. */
#define SHROOT_RAW_SYSCALLS 1
#include <pthreadP.h>
#include <cooperative_entry.h>
#include <elf.h>
#include <stddef.h>
#include <string.h>
#include <shroot-cancellation.h>

_Static_assert(offsetof(struct md_entry_api, offers) == 16, "assembly offer offset");
_Static_assert(offsetof(struct md_entry_api, syscall_count) == 24, "assembly count offset");
_Static_assert(offsetof(struct pthread, tid) == 208, "AArch64 pthread TID prefix ABI");

const struct md_entry_api *__shroot_entry attribute_hidden;
static int enabled;
unsigned shroot_libc_entry_abi(void) { return MD_ENTRY_VERSION; }

__attribute__((noinline)) static long
kernel_call(long nr, const uint64_t *args)
{
  return INTERNAL_SYSCALL_NCS_CALL(nr, args[0], args[1], args[2], args[3], args[4], args[5]);
}

#if SHROOT_MODERN_CANCEL
static long
cancellation_kernel(long nr, const uint64_t *args)
{
  struct pthread *self = THREAD_SELF;
  int ch = atomic_load_relaxed(&self->cancelhandling);
  if (SINGLE_THREAD_P || !cancel_enabled(ch) || cancel_exiting(ch))
    return kernel_call(nr, args);
  return __syscall_cancel_arch(&self->cancelhandling, nr,
                              args[0], args[1], args[2], args[3], args[4], args[5]);
}
#endif

void attribute_hidden
__shroot_init(char **environment)
{
  enabled = 1;
  char **p = environment;
  for (; *p; ++p)
    if (!strcmp(*p, "SHROOT_COOPERATIVE=0")) enabled = 0;
  for (Elf64_auxv_t *aux = (void *)(p + 1); aux->a_type; ++aux)
    if (aux->a_type == MD_AT_COOPERATIVE)
      {
        const struct md_entry_api *api = (void *)aux->a_un.a_val;
        if (md_entry_api_valid(api)) __shroot_entry = api;
        break;
      }
  if (!__shroot_entry) enabled = 0;
}

static long
invoke(long nr, const uint64_t *args, md_entry_kernel_fn kernel, void (*cancel)(void))
{
  struct pthread *self = THREAD_SELF;
  if (!enabled || (atomic_load_relaxed(&self->cancelhandling) & CANCELTYPE_BITMASK))
    return kernel(nr, args);
  struct md_entry_call call = {.number = nr, .kernel = kernel, .cancel = cancel};
  memcpy(call.args, args, sizeof(call.args));
  enum md_entry_outcome outcome = md_entry_invoke(__shroot_entry,&self->shroot_client, &call);
  if (outcome == MD_ENTRY_UNKNOWN) __builtin_trap();
  return outcome == MD_ENTRY_DECLINED ? kernel(nr, args) : call.result;
}

long attribute_hidden
__shroot_syscall(long nr, const uint64_t *args)
{
  return invoke(nr, args, kernel_call, NULL);
}

#if SHROOT_MODERN_CANCEL
int attribute_hidden
__shroot_cp_try(long nr, const uint64_t *args, long *result)
{
  if (!enabled || !md_entry_offered(__shroot_entry, nr, MD_ENTRY_CANCELLATION)) return 0;
  int ch = atomic_load_relaxed(&THREAD_SELF->cancelhandling);
  *result = !cancel_enabled(ch) || cancel_exiting(ch)
    ? cancellation_kernel(nr, args)
    : invoke(nr, args, cancellation_kernel, __pthread_testcancel);
  return 1;
}
#endif
