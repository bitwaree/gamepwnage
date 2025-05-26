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
            if(*(int*)_permissions == 0)
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

int __attribute__((visibility(VISIBILITY_FLAG))) get_prot(int addr)
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
