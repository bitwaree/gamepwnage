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
#include <sys/types.h>
#include <sys/stat.h>

#include "proc.h"
#include "armhook.h"

#if defined(__aarch64__)
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook64(uintptr_t addr, uintptr_t branchaddr, size_t len)
{
    const uint32_t nopBytes = 0xd503201f; // nop in aarch64
    const uint32_t shHookCode[3] = { 0x10000071, 0xf9400231, 0xd61f0220 };

    if (len%4 != 0 || len < 20) {
        //not alligned or not enough bytes
        return 0;
    }
    // get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    int old_protection = get_prot(aligned_addr);
    if(old_protection == -1) {
        // fprintf(stderr, "can't retrive memory protection, at address: %p\n", aligned_addr);
        return false;
    }
    if(!(old_protection & PROT_WRITE)) {
        // change memory protection to rwx
        if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            // protection change failed
            return false;
        }
    }
    // copy opcodes
    for(int i = 0; i < sizeof(shHookCode)/4; i++) {
        ((uint32_t*) addr)[i] = shHookCode[i];
    }
    *(uint64_t*)(addr + sizeof(shHookCode)) = branchaddr & 0xFFFFFFFFFFFFFFFF;    // copy the 64 bit address
    if(len > 20) {
        // nop the rest bytes
        for (int i = (sizeof(shHookCode) / 4) + 2; i < (len/4); i++) {
            ((uint32_t*) addr)[i] = nopBytes;
        }
    }
    if(!(old_protection & PROT_WRITE)) {
        // restore the original memory protection
        if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1) {
            // protection restoration failed
            return false;
        }
    }
    return addr + len;
}
#elif defined(__arm__)
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook32(uintptr_t addr, uintptr_t branchaddr, size_t len)
{
    const uint32_t nopBytes = 0xe1a00000; // nop in arm
    const uint32_t shHookCode[2] = { 0xe59fc000, 0xe12fff1c };

    if (len%4 != 0 || len<12) {
        // not alligned or not enough bytes
        return 0;
    }
    // get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    int old_protection = get_prot(aligned_addr);
    if(old_protection == -1) {
        // fprintf(stderr, "can't retrive memory protection, at address: %p\n", aligned_addr);
        return false;
    }
    if(!(old_protection & PROT_WRITE)) {
        // change memory protection to rwx
        if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            // protection change failed
            return false;
        }
    }
    // copy opcodes
    for(int i = 0; i < sizeof(shHookCode)/4; i++) {
        ((uint32_t*) addr)[i] = shHookCode[i];
    }
    *(uint32_t*)(addr + sizeof(shHookCode)) = branchaddr & 0xFFFFFFFF;    // copy the 32 bit address
    if(len > 12) {
        // nop the rest bytes
        for (int i = (sizeof(shHookCode) / 4) + 1; i < (len/4); i++) {
            ((uint32_t*) addr)[i] = nopBytes;
        }
    }
    if(!(old_protection & PROT_WRITE)) {
        // change memory protection to rwx
        if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            // protection change failed
            return false;
        }
    }
    return addr + len;
}
#endif
