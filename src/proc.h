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
#include <stdbool.h>


uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) get_module_addr(char *_module, char *_permissions);
int __attribute__((visibility(VISIBILITY_FLAG))) get_prot(int addr);
