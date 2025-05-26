/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include <stdint.h>
#include <stdbool.h>

bool write_mem(void *Dest, void *Src, size_t len);
bool read_mem(void *Dest, void *Src, size_t len);
uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset);
