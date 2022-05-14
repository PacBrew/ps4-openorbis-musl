#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include "syscall.h"

static void dummy(void) { }
weak_alias(dummy, __vm_wait);

#define UNIT SYSCALL_MMAP2_UNIT
#define OFF_MASK ((-0x2000ULL << (8*sizeof(syscall_arg_t)-1)) | (UNIT-1))

#ifndef PS4

void *__mmap(void *start, size_t len, int prot, int flags, int fd, off_t off)
{
	long ret;
	if (off & OFF_MASK) {
		errno = EINVAL;
		return MAP_FAILED;
	}
	if (len >= PTRDIFF_MAX) {
		errno = ENOMEM;
		return MAP_FAILED;
	}
	if (flags & MAP_FIXED) {
		__vm_wait();
	}
#ifdef SYS_mmap2
	ret = __syscall(SYS_mmap2, start, len, prot, flags, fd, off/UNIT);
#else
	ret = __syscall(SYS_mmap, start, len, prot, flags, fd, off);
#endif
	/* Fixup incorrect EPERM from kernel. */
	if (ret == -EPERM && !start && (flags&MAP_ANON) && !(flags&MAP_FIXED))
		ret = -ENOMEM;
	return (void *)__syscall_ret(ret);
}

weak_alias(__mmap, mmap);

weak_alias(mmap, mmap64);

#else
#ifdef PS4_FLEXIBLE_MEMORY

#define MEM_SIZE (0xA0000000) /* 2600 MiB */
#define MEM_ALIGN (16UL * 1024)
#define SCE_KERNEL_PROT_CPU_RW 0x02
#define SCE_KERNEL_MAP_FIXED 0x10

typedef void *OrbisMspace;
typedef struct OrbisMallocManagedSize {
    unsigned short sz;
    unsigned short ver;
    unsigned int reserv;
    size_t maxSysSz;
    size_t curSysSz;
    size_t maxUseSz;
    size_t curUseSz;
} OrbisMallocManagedSize;

size_t musl_s_malloc_size = 0;
OrbisMspace musl_s_mspace = 0;
static OrbisMallocManagedSize s_mmsize;
static void *s_mem_start = 0;
static size_t s_mem_size = MEM_SIZE;

int sceKernelReserveVirtualRange(void **, size_t, int, size_t);
int sceKernelMapNamedSystemFlexibleMemory(void **, size_t, int, int, const char *);
OrbisMspace sceLibcMspaceCreate(char *, void *, size_t, unsigned int);
int sceLibcMspaceMallocStatsFast(OrbisMspace, OrbisMallocManagedSize *);
void *sceLibcMspaceMalloc(OrbisMspace, size_t size);

static int mmap_init()
{
    int res;

    if (musl_s_mspace)
        return 0;

    res = sceKernelReserveVirtualRange(&s_mem_start, MEM_SIZE, 0, MEM_ALIGN);
    if (res < 0)
        return 1;

    res = sceKernelMapNamedSystemFlexibleMemory(
            &s_mem_start, MEM_SIZE, SCE_KERNEL_PROT_CPU_RW, SCE_KERNEL_MAP_FIXED, "User Mem");
    if (res < 0)
        return 1;

    musl_s_mspace = sceLibcMspaceCreate("User Mspace", s_mem_start, s_mem_size, 0);
    if (!musl_s_mspace)
        return 1;

    s_mmsize.sz = sizeof(s_mmsize);
    s_mmsize.ver = 1;
    res = sceLibcMspaceMallocStatsFast(musl_s_mspace, &s_mmsize);
    return 0;
}

#include <stdio.h>
#include <stdarg.h>

extern int sceKernelDebugOutText(int dbg_channel, const char* text);

static char debug_str[0x1000];

static void print(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(debug_str, 0x1000, fmt, args);
    va_end(args);
    sceKernelDebugOutText(0, debug_str);
}


void *__mmap(void *start, size_t len, int prot, int flags, int fd, off_t off)
{
  if (!musl_s_mspace)
    mmap_init();
  
  void *ptr = sceLibcMspaceMalloc(musl_s_mspace, len);
  if(start) {
    start = ptr;
  }
  
  musl_s_malloc_size += len;
  print("musl: mmap(%p, %li, %i, %i, %i, %li): ptr = %p, total = %li\n", 
    start, len, prot, flags, fd, off, ptr, musl_s_malloc_size);
    
  return ptr;
}

weak_alias(__mmap, mmap);

weak_alias(mmap, mmap64);

#else

void* mmap(void*, size_t, int, int, int, off_t);

void* __mmap(void* start, size_t len, int prot, int flags, int fd, off_t off)
{
	return mmap(start, len, prot, flags, fd, off);
}

weak_alias(__mmap, mmap64);

#endif
#endif
