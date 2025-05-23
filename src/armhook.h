/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/
#pragma once
#include "config.h"
#include <stddef.h>
// For 64 bit armhook: requires 28 bytes minimum
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook64(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len);

//For 32 bit armhook: requires 20 bytes minimum
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook32(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len);
