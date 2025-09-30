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
#include <string.h>
#include <sys/mman.h>
#include "proc.h"

__attribute__((visibility(VISIBILITY_FLAG)))
unsigned int get_proc_map_count(const char *module) {
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        //perror("Can't open map...");
        return 0;
    }

    char line[1024];
    unsigned int idx = 0;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (module) {
            if (!strstr(line, module))
                continue;
        }
        idx++;
    }
    fclose(fd);
    return idx;
}
__attribute__((visibility(VISIBILITY_FLAG)))
unsigned int get_proc_map(const char *module,
    proc_map *map_array, unsigned int max_map_count)  {
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd) {
        //perror("Can't open map...");
        return 0;
    }

    char line[1024];
    unsigned int idx = 0;
    char prot_str[5];
    while (fgets(line, sizeof(line), fd) != NULL && idx < max_map_count) {
        if (module) {
            if (!strstr(line, module))
                continue;
        }
        // <start_addr>-<end_addr> rwxp ....
        sscanf(line, "%lx-%lx %4s", &map_array[idx].start, &map_array[idx].end, prot_str);
        map_array[idx].prot = 0;
        if (prot_str[0] == 'r')
            map_array[idx].prot |= PROT_READ;
        if (prot_str[1] == 'w')
            map_array[idx].prot |= PROT_WRITE;
        if (prot_str[2] == 'x')
            map_array[idx].prot |= PROT_EXEC;
        idx++;
    }
    fclose(fd);
    return idx;
}

uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) get_module_addr(char *_module, char *_permissions)
{
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd)
    {
        //perror("Can't open map...");
        return 0;
    }

    char line[1024];
    char *start_addr_str = 0;
    char *end_addr_str = 0;

    while (fgets(line, sizeof(line), fd) != NULL)
    {
        char *library_name = strstr(line, _module);
        if (library_name != NULL)
        {
            if(_permissions == 0 || *(char*)_permissions == 0)
            {
                // if permission not specified,
                // it will return the first mapped address
                start_addr_str = strtok(line, "-");
                end_addr_str = strtok(NULL, " ");
                break;
            }
            char *protection = strstr(line, _permissions);
            if (protection != NULL)
            {
                start_addr_str = strtok(line, "-");
                end_addr_str = strtok(NULL, " ");
                break;
            }
        }
    }

    fclose(fd);
    // convert the hex into text
    uintptr_t start_addr = 0, end_addr = 0;
    sscanf(start_addr_str, "%lx", &start_addr);
    sscanf(end_addr_str, "%lx", &end_addr);

    return start_addr;
}

int __attribute__((visibility(VISIBILITY_FLAG))) get_prot(uintptr_t addr)
{
    FILE* fd = fopen("/proc/self/maps", "r");
    if (!fd)
    {
        //perror("Can't open map...");
        return -1;
    }

    char line[1024];
    // convert the hex into text
    uintptr_t start_addr, end_addr;
    char prot_str[5];

    while (fgets(line, sizeof(line), fd) != NULL)
    {
        // <start_addr>-<end_addr> rwxp ....
        sscanf(line, "%lx-%lx %4s", &start_addr, &end_addr, prot_str);
        if (addr >= start_addr && addr < end_addr )
            break;
    }

    fclose(fd);

    int prot = 0;
    if(prot_str[0] == 'r')
        prot |= PROT_READ;
    if(prot_str[1] == 'w')
        prot |= PROT_WRITE;
    if(prot_str[2] == 'x')
        prot |= PROT_EXEC;

    return prot;
}

__attribute__((visibility(VISIBILITY_FLAG)))
void* find_unmapped(void *target, size_t size) {
    unsigned int map_count = get_proc_map_count(0);
    proc_map *maps = calloc(map_count, sizeof(proc_map));
    if(!maps) {
        // calloc() failed
        return 0;
    }
    unsigned int rd_map_count = get_proc_map(0, maps, map_count);
    unsigned int target_index = -1;
    // get the target's index
    for(unsigned int i = 0; i < rd_map_count; i++) {
        if((uintptr_t) target >= maps[i].start &&
            (uintptr_t) target < maps[i].end
        ) {
            target_index = i;
            break;
        }
    }
    if(target_index == -1) {
        // target map not found
        free(maps);
        return 0;
    }
    uintptr_t nearest_pos = 0, nearest_neg = 0;
    if(target_index < rd_map_count) {
        // find positive
        for(unsigned int i = target_index; i < rd_map_count; i++) {
            if(maps[i+1].start - maps[i].end >= size) {
                nearest_pos = maps[i].end;
                break;
            }
        }
    } else {
        nearest_pos = maps[target_index].end;
    }
    if(target_index > 0) {
        // find negative
        for(unsigned int i = target_index - 1; i == 0; i--) {
            if(maps[i+1].start - maps[i].end >= size) {
                nearest_neg = maps[i].end;
                break;
            }
        }
    } else if (maps[target_index].start >= size) {
        nearest_neg = maps[target_index].start - size;
    }
    free(maps);
    if(nearest_pos - (uintptr_t) target <= (uintptr_t) target - nearest_neg)
    {
        return (void*) nearest_pos;
    } else {
        return (void*) nearest_neg;
    }
}
