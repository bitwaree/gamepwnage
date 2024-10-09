/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mem.h"

BOOL __attribute__((visibility(VISIBILITY_FLAG))) WritetoMemory(void *Dest, void *Src, size_t Size, int old_protection)
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
        perror("WritetoMemory: Error changing memory protection");
        printf("mprotect error code: %d\n", errno);
        return FALSE;
    }

    // Perform your memory modification here
    // ...
    memcpy(Dest, Src, Size);

    // Restore the original memory protection
    if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1)
    {
        perror("WritetoMemory: Error restoring memory protection");
        printf("mprotect error code: %d\n", errno);
        return FALSE;
    }

    return TRUE;
}

BOOL __attribute__((visibility(VISIBILITY_FLAG))) ReadfromMemory(void *Dest, void *Src, size_t Size, int old_protection)
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
        perror("ReadfromMemory: Error changing memory protection");
        printf("mprotect error code: %d\n", errno);
        return FALSE;
    }
    memcpy(Dest, Src, Size);
    // Restore the original memory protection
    if (mprotect((void *)aligned_addr, aligned_size, old_protection) == -1)
    {
        perror("ReadfromMemory: Error restoring memory protection");
        printf("mprotect error code: %d\n", errno);
        return FALSE;
    }
    return TRUE;
}

BOOL __attribute__((visibility(VISIBILITY_FLAG))) PatchNop(void *Address, size_t len)
{
//Check architecture and set-up as required
#if defined(__x86_64__) || defined(__amd64__)
    // Code specific to x86_64
    static const unsigned char nopBytes[1] = {0x90};
    static const size_t nopBytes_len = 1;
#elif defined(__i386__) || defined(__i686__) || defined (__x86__)
    // Code specific to x86 (32-bit)
    static const unsigned char nopBytes[1] = {0x90};
    static const size_t nopBytes_len = 1;
#elif defined(__aarch64__)
    // Code specific to AArch64
    static const unsigned char nopBytes[4] = {0x1f, 0x20, 0x03, 0xd5};
    static const size_t nopBytes_len = 4;
#elif defined(__arm__)
    // Code specific to 32-bit ARM
    static const unsigned char nopBytes[4] = {0x00, 0x00, 0xa0, 0xe1};
    static const size_t nopBytes_len = 4;
#elif defined(__mips__)
    // Code specific to MIPS
    static const unsigned char nopBytes[4] = {0x00, 0x00, 0x00, 0x00};
    static const size_t nopBytes_len = 4;
#else
    #error "Unsupported architecture."
#endif

    if((len % nopBytes_len) != 0)
    {
        //If invalid length
        fprintf(stderr, "[!] %s@%s: Invalid nop length specified at address 0x%lX! (must be a multiple of %d)", 
            "PatchNop", "gamepwnage", (uintptr_t)Address, (int)nopBytes_len);
        return FALSE;
    }
    
   // Get the system page size
    size_t page_size = sysconf(_SC_PAGESIZE);
    
    // Calculate the aligned address and size
    uintptr_t addr = (uintptr_t)Address;
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = ((addr + len + page_size - 1) & ~(page_size - 1)) - aligned_addr;

    // Change memory protection to allow reading, writing, and executing
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        perror("[X] PatchNop: Error changing memory protection");
        return FALSE;
    }

    for (int n=0; n < (len/nopBytes_len); n++)
    {
        //copy nop bytes
        memcpy(Address, nopBytes, nopBytes_len);
        Address += nopBytes_len;
    }

    // Restore the original memory protection
    if (mprotect((void *)aligned_addr, aligned_size, PROT_READ | PROT_EXEC) == -1)
    {
        perror("[X] PatchNop: Error restoring memory protection");
        return FALSE;
    }

    return TRUE;
}

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) GetAddress(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
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

bool __attribute__((visibility(VISIBILITY_FLAG))) HookAddress(void *AddresstoHook, void *hookFunAddr, size_t len)
{
    if (len < 5)
    {
        return false;
    }
    // Change Permission
    int old_protection;
    old_protection = mprotect(AddresstoHook, len, 0);
    if (old_protection == -1)
    {
        perror("Error getting old memory protection");
        return 0;
    }
    // Change the protection of the region
    if (mprotect(AddresstoHook, len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        perror("Error changing memory protection");
        return 0;
    }
    // patch nops
    memset(AddresstoHook, 0x90, len);

    uint32_t RelativeAddress = ((uintptr_t)hookFunAddr - ((uintptr_t)AddresstoHook + 5)); // get the relative address

    *(BYTE *)AddresstoHook = 0xE9; // copy jmp instruction
    memcpy((void *)((uintptr_t)AddresstoHook + 1), &RelativeAddress, sizeof(uint32_t));
    // Restore the previous permisssion
    if (mprotect(AddresstoHook, len, old_protection) == -1)
    {
        perror("Error changing memory protection");
        return 0;
    }
    return true;
}

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) GetModuleBaseAddress(char *_library, char *_permissions)
{
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd)
    {
        perror("Cann't open map...");
        return 1;
    }

    char line[1024];
    char *start_addr_str = 0;
    char *end_addr_str = 0;

    while (fgets(line, sizeof(line), fd) != NULL)
    {
        char *library_name = strstr(line, _library);
        if (library_name != NULL)
        {
            char *protection = strstr(line, _permissions);
            if (protection != NULL)
            {
                start_addr_str = strtok(line, "-");
                end_addr_str = strtok(NULL, " ");
                // printf("Library %s with protection %s: start address 0x%s, end address 0x%s\n", LIBRARY_NAME, PROTECTION, start_addr_str, end_addr_str);
                break;
            }
        }
    }

    fclose(fd);
    // convert the hex into text
    uintptr_t start_addr, end_addr;
    sscanf(start_addr_str, "%lx", &start_addr);
    sscanf(end_addr_str, "%lx", &end_addr);
    
    return start_addr;
}

