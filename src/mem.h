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


#ifndef CONFIG_H_
//config.h not included
//default configs

//TODO: add default configs
#endif

// #ifndef TRUE
// #define TRUE true;
// #endif
// #ifndef FALSE
// #define FALSE false;
// #endif

// #ifndef BYTE
// #define BYTE uint8_t;
// #endif
// #ifndef BOOL
// #define BOOL bool;
// #endif

// typedef uint8_t BYTE;
// typedef bool BOOL;


bool __attribute__((visibility(VISIBILITY_FLAG))) write_mem(void *Dest, void *Src, size_t len);
bool __attribute__((visibility(VISIBILITY_FLAG))) read_mem(void *Dest, void *Src, size_t len);

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset);
