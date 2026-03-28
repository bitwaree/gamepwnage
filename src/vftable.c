/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2026 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
 */

#ifdef GPWN_USING_BUILD_CONFIG
#include "config.h"
#else
#ifndef GPWNAPI
#define GPWNAPI
#endif
#ifndef GPWN_BKND
#define GPWN_BKND
#endif
#endif

#include <stdio.h>
#include <string.h>

#include "vftable.h"
#include "dynlib.h"
#include "mem.h"


GPWNAPI void **get_vftable_ptr(const char *libname, const char *classname) {
    char sym[4096];
    size_t class_len = strnlen(classname, 4096);
    if(
        !classname || !*classname ||
        class_len >= 4096 - 7) {
        return 0;   // symbol too long
    }

    sprintf(sym, "_ZTV%zu%s", class_len, classname);
    void *vtable_addr = gpwn_dlsym(libname, (const char*) sym);
    return (vtable_addr) ? vtable_addr + 2*sizeof(void*) : 0;
}

GPWNAPI void *hook_vft(void **vftable, size_t idx, void *newfunc) {
    void *old_func = vftable[idx];

    if(!write_mem((void*) &vftable[idx],
        (void*) &newfunc, sizeof(void*))
    ) return 0;
    return old_func;
}
