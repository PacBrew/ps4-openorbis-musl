#include <sys/mman.h>
#include "syscall.h"

static void dummy(void) { }
weak_alias(dummy, __vm_wait);

#ifndef PS4

int __munmap(void *start, size_t len)
{
	__vm_wait();
	return syscall(SYS_munmap, start, len);
}

weak_alias(__munmap, munmap);

#else
#ifdef PS4_FLEXIBLE_MEMORY

#include <stdio.h>
#include <stdint.h>
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

typedef void *OrbisMspace;
int sceLibcMspaceFree(OrbisMspace, void *);
extern OrbisMspace musl_s_mspace;
extern size_t musl_s_malloc_size;

int __munmap(void *start, size_t len)
{
  if(!musl_s_mspace || !start) {
    return -1;
  }
  
  if((uintptr_t)start > 0x880000000) {
    print("WARNING: munmap(%li): ptr = %p\n", len, start);
    return -1;
  }
  
  musl_s_malloc_size -= len;
  
  print("musl: munmap(%li): ptr = %p, total = %li\n", len, start, musl_s_malloc_size);
    
  sceLibcMspaceFree(musl_s_mspace, start);
  return 0;
}

weak_alias(__munmap, munmap);

#else
int munmap(void* start, size_t len);

int __munmap(void* start, size_t len)
{
	return munmap(start, len);
}

#endif
#endif
