/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mem.h"
#include "proc.h"

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook64(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len)
{
    const uint32_t nopBytes = 0xd503201f; // nop in aarch64
    const uint32_t shHookCode[3] = { 0x10000071, 0xf9400231, 0xd61f0220 };

    if (len%4 != 0 || len < 20)
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
    memcpy(pseudomem, shHookCode, sizeof(shHookCode));
    *((uint64_t*)(pseudomem + sizeof(shHookCode))) = hookFunAddr & 0xFFFFFFFFFFFFFFFF;  // copy the 64 bit address

    if(write_mem((void *) AddresstoHook, (void *) pseudomem, len) != 1)
    {
        free(pseudomem);
        return 0;
    }
    free(pseudomem);

    return AddresstoHook + sizeof(shHookCode) + 8;   // return at the pop instruction
}

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook32(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len)
{
    const uint32_t nopBytes = 0xe1a00000; // nop in arm
    const uint32_t shHookCode[2] = { 0xe59fc000, 0xe12fff1c };

    if (len%4 != 0 || len<12)
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
    memcpy(pseudomem, shHookCode, sizeof(shHookCode));
    *((uint32_t*)(pseudomem + sizeof(shHookCode))) = hookFunAddr & 0xFFFFFFFF;          // copy the 32 bit address

    if(write_mem((void *) AddresstoHook, (void *) pseudomem, len) != 1)
    {
        free(pseudomem);
        return 0;
    }
    free(pseudomem);

    return AddresstoHook + sizeof(shHookCode) + 4;   // return at the pop instruction
}
