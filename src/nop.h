/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "config.h"

bool __attribute__((visibility(VISIBILITY_FLAG))) patch_nop(void *Address, size_t len);
