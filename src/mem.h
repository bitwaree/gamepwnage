/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include "config.h"
#include <stdint.h>
#include <stdbool.h>


#ifndef CONFIG_H_
//config.h not included
//default configs

//TODO: add default configs
#endif

typedef bool BOOL;
#define TRUE true;
#define FALSE false;
typedef uint8_t BYTE;


#ifdef NO_EXPORT_SYM
    #define VISIBILITY_FLAG "hidden"
#else
    #define VISIBILITY_FLAG "default"
#endif

BOOL __attribute__((visibility(VISIBILITY_FLAG))) WritetoMemory(void *Dest, void *Src, size_t Size, int old_protection);
BOOL __attribute__((visibility(VISIBILITY_FLAG))) ReadfromMemory(void *Dest, void *Src, size_t Size, int old_protection);
BOOL __attribute__((visibility(VISIBILITY_FLAG))) PatchNop(void *Address, size_t len);
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) GetAddress(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset);

bool __attribute__((visibility(VISIBILITY_FLAG))) HookAddress(void *AddresstoHook, void *hookFunAddr, size_t len);
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) GetModuleBaseAddress(char *_library, char *_permissions);
