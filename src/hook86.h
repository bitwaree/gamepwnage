/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include "config.h"
#include <stdint.h>

/*
x86_32 hook -- atleast 5 bytes required to place a hook
            -- no gp registers will be modified

RETURNS     -- the address where the hook should jmp back
*/
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) hook_x86(void *AddresstoHook, void *hookFunAddr, size_t len);

/*
x86_64 hook -- atleast 16 bytes required to place a hook
            -- "%rax" will be modified,
               needs to be poped in the first of the code
            -- "%rsp" will be modified as well

RETURNS     -- the address where the hook should jmp back
*/
#if defined(__x86_64__) || defined(__amd64__)
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) hook_x64(void *AddresstoHook, void *hookFunAddr, size_t len);
#endif
