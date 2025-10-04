/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#ifdef GPWN_USING_BUILD_CONFIG
#include "config.h"
#else
#ifndef GPWNAPI
#define GPWNAPI
#endif
#ifndef GPWN_BKND
#define GPWN_BKND
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

#include "hook86.h"
#include "proc.h"

/*
x86_32 hook -- atleast 5 bytes required to place a hook
            -- no gp registers will be modified

RETURNS     -- the address where the hook should jmp back
*/
GPWNAPI uintptr_t hook_x86(void *AddresstoHook, void *hookFunAddr, size_t len)
{
    if (len < 5)
    {
        // not enough bytes
        // fprintf(stderr, "hook_x86() error: not enough memory to place a hook\n");
        return 0;
    }

    // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)AddresstoHook;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    // the the current protection
    int old_protection;
    old_protection = get_prot(aligned_addr);
    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *) aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        // perror("Error changing memory protection");
        return 0;
    }
    // patch nops
    memset(AddresstoHook, 0x90, len);

    uint32_t RelativeAddress = ((uintptr_t)hookFunAddr - ((uintptr_t)AddresstoHook + 5)); // get the relative address

    *(unsigned char *)AddresstoHook = 0xE9; // copy jmp instruction
    memcpy((void *)((uintptr_t)AddresstoHook + 1), &RelativeAddress, 4);
    // Restore the previous permisssion
    if (mprotect((void *) aligned_addr, len, old_protection) == -1)
    {
        // perror("Error changing memory protection");
        // won't returns "0" as hook already placed
    }
    return (uintptr_t)AddresstoHook + len;
}


/*
x86_64 hook -- atleast 16 bytes required to place a hook
            -- "%rax" will be modified,
               needs to be poped in the first of the code
            -- "%rsp" will be modified as well

RETURNS     -- the address where the hook should jmp back
*/
#if defined(__x86_64__) || defined(__amd64__)
GPWNAPI uintptr_t hook_x64(void *AddresstoHook, void *hookFunAddr, size_t len)
{
    static const unsigned char jmp_sample[14] = {  
        0x50, 0x48, 0xb8, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0xff,
        0xe0, 0x58
    };
    
    if (len < 14)
    {
        // not enough bytes
        // fprintf(stderr, "hook_x64() error: not enough memory to place a hook\n");
        return 0;
    }
    // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)AddresstoHook;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    // the the current protection
    int old_protection;
    old_protection = get_prot(aligned_addr);
    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *) aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        // perror("Error changing memory protection");
        return 0;
    }
    // patch nops
    memset(AddresstoHook, 0x90, len);
    // copy sample jmp instruction
    memcpy((void*)AddresstoHook, (void*) jmp_sample, sizeof(jmp_sample));
    //copy the addressss to jmp
    memcpy((void *)((uintptr_t)AddresstoHook + 3), &hookFunAddr, 8);
    // Restore the previous permisssion
    if (mprotect((void *) aligned_addr, len, old_protection) == -1)
    {
        // perror("Error changing memory protection");
        // won't returns "0" as hook already placed
    }
    return ((uintptr_t)AddresstoHook + 0xD);    //Return the jumpback address
}
#endif
