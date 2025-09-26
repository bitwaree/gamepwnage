/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

#include "mem.h"
#include "proc.h"
#include "inlinehook.h"

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
#include "hook86.h"
#elif defined(__arm__) || defined (__aarch64__)
#include "armhook.h"
#endif
#if defined(__arm__) && !defined(__aarch64__)
#define HOOKBYTES_LEN 12
#define HOOK_JMPBACKADDR_OFFSET HOOKBYTES_LEN
#elif defined(__aarch64__) && !defined(__arm__)
#define HOOKBYTES_LEN 20
#define HOOK_JMPBACKADDR_OFFSET HOOKBYTES_LEN
#endif

// typedef struct {
//     void *address;          // where to place hook
//     void *fake;             // the detour
//     void *trampoline_addr;  // allocated address to place the copied bytes
// } hook_handle;

hook_handle* __attribute__((visibility(VISIBILITY_FLAG))) hook_addr(void *address, void *fake, void **original_func) {
    hook_handle *handle = malloc(sizeof(hook_handle));
    if(!handle) {
        // perror("malloc() failed.");
        return 0;
    }
    handle->address = address;
    handle->fake = fake;
    size_t page_size = (size_t) sysconf(_SC_PAGESIZE);
    void *aligned_addr = (void*) ((uintptr_t) address & ~(page_size - 1));
    // allocate the trampoline
    handle->trampoline_addr = mmap(aligned_addr, page_size, PROT_EXEC | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(handle->trampoline_addr == MAP_FAILED) {
        // perror("mmap() failed.");
        free(handle);
        return 0;
    }
    // read the bytes
    uint8_t mem_buffer[HOOKBYTES_LEN];
    if(read_mem(mem_buffer, address, HOOKBYTES_LEN) == 0) {
        // fputs("read_mem() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
    if(write_mem(handle->trampoline_addr, mem_buffer, HOOKBYTES_LEN) == 0) {
        // fputs("write_mem() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }

    // place the hook
#ifdef __arm__
    if(!arm_hook32((uintptr_t) handle->trampoline_addr + HOOKBYTES_LEN, (uintptr_t) address + HOOK_JMPBACKADDR_OFFSET, HOOKBYTES_LEN)) {
        // fputs("arm_hook32() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
    if(!arm_hook32((uintptr_t) address, (uintptr_t) fake, HOOKBYTES_LEN)) {
        // fputs("arm_hook32() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
#elifdef __aarch64__
    if(!arm_hook64((uintptr_t) (handle->trampoline_addr + HOOKBYTES_LEN), (uintptr_t) (address + HOOK_JMPBACKADDR_OFFSET), HOOKBYTES_LEN)) {
        // fputs("arm_hook64() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
    if(!arm_hook64((uintptr_t) address, (uintptr_t) fake, HOOKBYTES_LEN)) {
        // fputs("arm_hook64() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
#endif
    *original_func = handle->trampoline_addr;
    return handle;
}

bool __attribute__((visibility(VISIBILITY_FLAG))) rm_hook(hook_handle *handle) {
    uint8_t mem_buffer[HOOKBYTES_LEN];
    if(read_mem(mem_buffer, handle->trampoline_addr, HOOKBYTES_LEN)) {
        // fputs("read_mem() failed.\n", stderr);
        return 0;
    }
    if(write_mem(handle->address, mem_buffer, HOOKBYTES_LEN)) {
        // fputs("write_mem() failed.\n", stderr);
        return 0;
    }
    munmap(handle->trampoline_addr, sysconf(_SC_PAGESIZE));
    free(handle);
    return 1;
}

