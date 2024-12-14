#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sys/mman.h>

#include "mem.h"


uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook64(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len)
{
    const uint32_t nopBytes = 0xd503201f; // nop in aarch64
    const uint32_t popBytes = 0xf85f83e0; // ldr x0, [sp, #-8]
    const uint32_t shHookCode[4] = { 0xf81f83e0, 0x10000060, 0xf9400000, 0xd61f0000 };

    if (len%4 != 0 || len<28)
    {
        //not alligned or not enough bytes
        return 0;
    }
    unsigned char *pseudomem = malloc(len);
    // nop the bytes
    for (int i = 0; i < (len/4); i++) {
        // loop through 4 byte nop blocks
        *((uint32_t*) (pseudomem + (i*4))) = nopBytes & 0xFFFFFFFF;     // copy the 32 bit nop opcodes
    }

    //overlay shellcode
    memcpy(pseudomem, shHookCode, 16);
    *((uint64_t*)(pseudomem + 16)) = hookFunAddr & 0xFFFFFFFFFFFFFFFF;  // copy the 64 bit address
    *((uint32_t*)(pseudomem + 24)) = popBytes & 0xFFFFFFFF;             // copy the 32 bit pop opcodes

    if(WritetoMemory((void *) AddresstoHook, (void *) pseudomem, len, PROT_READ | PROT_EXEC ) != 1)
    {
        free(pseudomem);
        return 0;
    }
    free(pseudomem);

    return AddresstoHook + 24;   // return at the pop instruction
}

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook32(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len)
{
    const uint32_t nopBytes = 0xe1a00000; // nop in arm
    const uint32_t popBytes = 0xe59d0ffc; // ldr r0, [sp], #4
    const uint32_t shHookCode[3] = { 0xe58d0ffc, 0xe59f0000, 0xe12fff10 };

    if (len%4 != 0 || len<20)
    {
        //not alligned or not enough bytes
        return 0;
    }
    unsigned char *pseudomem = malloc(len);
    // nop the bytes
    for (int i = 0; i < (len/4); i++) {
        // loop through 4 byte nop blocks
        *((uint32_t*) (pseudomem + (i*4))) = nopBytes & 0xFFFFFFFF;     // copy the 32 bit nop opcodes
    }

    //overlay shellcode
    memcpy(pseudomem, shHookCode, 12);
    *((uint32_t*)(pseudomem + 12)) = hookFunAddr & 0xFFFFFFFF;          // copy the 64 bit address
    *((uint32_t*)(pseudomem + 16)) = popBytes & 0xFFFFFFFF;             // copy the 32 bit pop opcodes

    if(WritetoMemory((void *) AddresstoHook, (void *) pseudomem, len, PROT_READ | PROT_EXEC ) != 1)
    {
        free(pseudomem);
        return 0;
    }
    free(pseudomem);

    return AddresstoHook + 16;   // return at the pop instruction
}

