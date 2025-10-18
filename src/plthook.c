/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

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
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#if defined(__linux__)
#define __USE_GNU
#endif
#include <link.h>
#include <dlfcn.h>

#include "plthook.h"

GPWNAPI plthook_handle *hook_plt(
    const char *libname, const char *symname,
    void *fake, void **original
) {
    ElfW(Addr) baddr = 0;
    ElfW(Dyn) *dyn = 0;
    ElfW(Sym) *symtab = 0;
    char *strtab = 0;
    ElfW(Rela) *rela_plt = 0;
    size_t rela_plt_size = 0;

    if(libname && *libname != '\0') {
        // lib is specified
        void *dlhandle = dlopen(libname, RTLD_NOLOAD | RTLD_LAZY);
        if(!dlhandle) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "hook_plt() dlopen() on library \"%s\" failed\n", libname);
#endif
            return 0;
        }
        struct link_map *lmap = 0;
        if(dlinfo(dlhandle, RTLD_DI_LINKMAP, &lmap)) {
#ifdef GPWN_DEBUG
            fprintf(stderr, "hook_plt() dlinfo() couldn't retrive link_map\n");
#endif
            dlclose(dlhandle);
            return 0;
        }
        dlclose(dlhandle);
        baddr = lmap->l_addr;
        dyn = lmap->l_ld;
    } else {
        // lib not specified
        struct link_map *lmap = _r_debug.r_map;
        baddr = lmap->l_addr;
        dyn = lmap->l_ld;
    }
    // retrive sections
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_SYMTAB)
            symtab = (ElfW(Sym) *)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_STRTAB)
            strtab = (char *)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_JMPREL)
            rela_plt = (ElfW(Rela) *)dyn->d_un.d_ptr;
        if (dyn->d_tag == DT_PLTRELSZ)
            rela_plt_size = dyn->d_un.d_val;
    }
    // iterate through relocation table
    void **r_addr = 0;
    for (size_t i = 0; i < rela_plt_size / sizeof(ElfW(Rela)); i++) {
        ElfW(Rela) *rel = &rela_plt[i];
        uint32_t sym_idx = ELF64_R_SYM(rel->r_info);   // index
        ElfW(Sym) *sym = &symtab[sym_idx];
        const char *_symname = &strtab[sym->st_name];

        if (strncmp(_symname, symname, strlen(symname)) == 0 &&
            (_symname[strlen(symname)] == '\0' || _symname[strlen(symname)] == '@')
        )
            r_addr =  (void **) (rel->r_offset + baddr);
    }
    if(!r_addr) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "hook_plt() failed : no such symbol as"
                " \"%s\" in \"%s\"\n", symname, libname);
#endif
        return 0;
    }
// #ifdef GPWN_DEBUG
//     printf("%s@%s : %p\n", symname, libname, r_addr);
// #endif
    plthook_handle *handle = malloc(sizeof(plthook_handle));
    if(!handle) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "hook_plt() failed : malloc() failed\n");
#endif
        return 0;
    }
    handle->addr = r_addr;
    handle->original = *r_addr;

    if(original)
        *original = *r_addr;
    *r_addr = fake;
    return handle;
}

GPWNAPI void rm_hook_plt(plthook_handle *handle) {
    if(handle) {
        *handle->addr = handle->original;
        free(handle);
    }
}
