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
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mem.h"
#include "proc.h"

GPWNAPI bool write_mem(void *Dest, void *Src, size_t len)
{
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)Dest;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    // get the current protection
    int old_protection = get_prot(aligned_addr);
    if(old_protection == -1)
    {
        // fprintf(stderr, "can't retrive memory protection, at address: %p\n", aligned_addr);
        return false;
    }

    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        /*
        perror("WritetoMemory: Error changing memory protection");
        printf("mprotect error code: %d\n", errno);
        */
        return false;
    }

    // Perform your memory modification here
    // ...
    memcpy(Dest, Src, len);

    // Restore the original memory protection
    if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1)
    {
        /*
        perror("WritetoMemory: Error restoring memory protection");
        printf("mprotect error code: %d\n", errno);
        */
        return false;
    }

    return true;
}
GPWNAPI bool read_mem(void *Dest, void *Src, size_t len)
{
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)Src;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;
    // get the current protection
    int old_protection = get_prot(aligned_addr);
    if(old_protection == -1)
    {
        // fprintf(stderr, "can't retrive memory protection at address: %p\n", aligned_addr);
        return false;
    }

    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        /*
        perror("ReadfromMemory: Error changing memory protection");
        printf("mprotect error code: %d\n", errno);
        */
        return false;
    }
    memcpy(Dest, Src, len);
    // Restore the original memory protection
    if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1)
    {
        /*
        perror("ReadfromMemory: Error restoring memory protection");
        printf("mprotect error code: %d\n", errno);
        */
        return false;
    }
    return true;
}
GPWNAPI uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
{

    int i = 0;
    uintptr_t Address = Baseaddr; // Get the base address from the parameters

    do
    {
        Address = *((uintptr_t *)Address); // Dereferance current address
        if (Address == (uintptr_t)NULL)
        {
            return 0;
        } // If address = NULL then return 0;

        Address += offsets[i]; // Address = Address + offset
        i++;

    } while (i < TotalOffset);

    return Address; // Return Final Address
}
GPWNAPI void *mmap_near(void *hint, size_t size, int prot) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t aligned_addr = (uintptr_t) hint & ~(page_size - 1);
    size_t aligned_size = (((uintptr_t)hint + size + page_size - 1) &
        ~(page_size - 1)) - aligned_addr;
    uintptr_t nearby = ((uintptr_t) find_unmapped((void*) aligned_addr, aligned_size)
        & ~(page_size - 1));
    return mmap((void*) nearby, aligned_size, prot,
        MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
}
