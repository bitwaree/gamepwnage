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
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>


#include "mem.h"

bool __attribute__((visibility(VISIBILITY_FLAG))) write_mem(void *Dest, void *Src, size_t Size, int old_protection)
{
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)Dest;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + Size + page_size - 1) & ~(page_size - 1)) - aligned_addr;

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
    memcpy(Dest, Src, Size);

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

bool __attribute__((visibility(VISIBILITY_FLAG))) read_mem(void *Dest, void *Src, size_t Size, int old_protection)
{
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)Src;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + Size + page_size - 1) & ~(page_size - 1)) - aligned_addr;

    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        /*
        perror("ReadfromMemory: Error changing memory protection");
        printf("mprotect error code: %d\n", errno);
        */
        return false;
    }
    memcpy(Dest, Src, Size);
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

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
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
