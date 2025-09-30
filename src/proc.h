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

typedef struct {
    uintptr_t start; /* starting addr of the map */
    uintptr_t end;   /* ending addr of the map   */
    int prot;        /* protection of the map    */
} proc_map;

unsigned int get_proc_map_count(const char *module);
unsigned int get_proc_map(const char *module, proc_map *map_array, unsigned int max_map_count);
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) get_module_addr(char *_module, char *_permissions);
int __attribute__((visibility(VISIBILITY_FLAG))) get_prot(uintptr_t addr);
void *find_unmapped(void *target, size_t size);
