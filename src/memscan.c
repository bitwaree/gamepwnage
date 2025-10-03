/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/mman.h>

#include "proc.h"
#include "memscan.h"

ssize_t parse_sigpattern(const char *in_pattern, byte **sigbyte, byte **mask);
/*
size_t search_sigpattern(byte *data, size_t data_len,
    byte *sigbyte, byte *mask, size_t sig_len);
*/
size_t search_sigpattern4(uint32_t *data, size_t data_len,
    uint32_t *sigbyte, uint32_t *mask, size_t sig_len);
size_t search_sigpattern_hybrid(byte *data, size_t data_len,
    byte *sigbyte, byte *mask, size_t sig_len);

sigscan_handle *sigscan_setup(const char *pattern_str,
    const char *libname, int flags) {
    sigscan_handle *handle = malloc(sizeof(sigscan_handle));
    if(!handle) {
        // allocation failed
        return 0;
    }
    handle->flags = flags;
    handle->next = 0;
    if(libname)
        handle->libname = strdup(libname);
    else
        handle->libname = 0;
    handle->memrange.start = 0;
    handle->memrange.end = 0;
    handle->sig_size = parse_sigpattern(pattern_str, &handle->sig, &handle->mask);
    if(handle->sig_size == -1) {
        // invalid sig
        free(handle->libname);
        free(handle);
        return 0;
    }
    return handle;
}
sigscan_handle *sigscan_setup_raw(byte *sigbyte, byte *mask, size_t sig_size,
    uintptr_t start_addr, uintptr_t end_addr, int flags) {
    sigscan_handle *handle = malloc(sizeof(sigscan_handle));
    if(!handle) {
        // allocation failed
        return 0;
    }
    handle->flags = flags;
    handle->next = 0;
    handle->libname = 0;
    if(end_addr <= start_addr)
        return 0;
    handle->memrange.start = (void*) start_addr;
    handle->memrange.end = (void*) end_addr;
    handle->sig = malloc(sig_size);
    if(!handle->sig) {
        // allocation failed
        free(handle);
        return 0;
    }
    handle->mask = malloc(sig_size);
    if(!handle->mask) {
        // allocation failed
        free(handle->sig);
        free(handle);
        return 0;
    }
    memcpy(handle->sig, sigbyte, sig_size);
    memcpy(handle->mask, mask, sig_size);
    handle->sig_size = sig_size;

    return handle;
}
void sigscan_cleanup(sigscan_handle *handle) {
    if(handle->libname)
        free(handle->libname);
    free(handle->sig);
    free(handle->mask);
    free(handle);
}

void *get_sigscan_result(sigscan_handle *handle) {
    if(handle->next == (void*)-1)
        return (void*)-1;          // all possible addresses has been scanned
    // parse protection flags
    int prot = 0;
    if(handle->flags & GPWN_SIGSCAN_WMEM)
        prot |= PROT_WRITE;
    if(handle->flags & GPWN_SIGSCAN_XMEM)
        prot |= PROT_EXEC;
    // if range specified (override)
    if(handle->memrange.start) {
        int _prot = get_prot((uintptr_t) handle->memrange.start);
        if((_prot & PROT_READ))
            return (void*) -1;
        if(prot && (_prot & prot) != prot)
            return (void*) -1;      // protection mismatch
        size_t offset;
        if(!handle->next) {
            // first scan
            offset = search_sigpattern_hybrid(handle->memrange.start,
                handle->memrange.end - handle->memrange.start,
                handle->sig, handle->mask, handle->sig_size);
        } else if (handle->next >= handle->memrange.start
            && handle->next <= handle->memrange.end - handle->sig_size
        ) {
            // continue if valid
            offset = search_sigpattern_hybrid(handle->next,
                handle->memrange.start - handle->memrange.end,
                handle->sig, handle->mask, handle->sig_size);
        } else {
            offset = -1;
        }
        if(offset == -1) {
            handle->next = (void*)-1;
            return (void*) -1;
        }
        handle->next = handle->memrange.start + offset + 1;
        return handle->memrange.start + offset;
    }
    unsigned int map_count = get_proc_map_count(handle->libname);
    if(!map_count)
        return (void*) -1;
    proc_map *maps = calloc(map_count, sizeof(proc_map));
    if(!maps)
        return (void*) -1;
    map_count = get_proc_map(handle->libname, maps, map_count);
    if(!map_count) {
        free(maps);
        return (void*) -1;
    }
    // scan all memory which is readable and satisfies the prot flags
    for(unsigned int i = 0; i < map_count; i++) {
        if((maps[i].prot & PROT_READ)) {
            if(prot && (maps[i].prot & prot) != prot)
                continue;       // protection mismatch
            byte *data;
            size_t data_len;
            size_t offset;
            if(!handle->next || (uintptr_t) handle->next < maps[i].start) {
                data = (byte*) maps[i].start;
                data_len = maps[i].end - maps[i].start;
            } else if (
                (uintptr_t) handle->next >= maps[i].start
                && (uintptr_t) handle->next <= maps[i].end - handle->sig_size
            ) {
                // continue scan
                data = (byte*) handle->next;
                data_len = maps[i].end - (size_t) handle->next;
            } else {
                continue;
            }
            // in force mode override the memory prot
            if(handle->flags & GPWN_SIGSCAN_FORCEMODE) {
                if(mprotect(
                        (void*) maps[i].start,
                        (maps[i].end - maps[i].start),
                        maps[i].prot | PROT_READ
                    ) == -1)
                    continue;
            }
            offset = search_sigpattern_hybrid(data, data_len,
                handle->sig, handle->mask, handle->sig_size);
            if(offset != -1) {
                handle->next = data + offset + 1;
                free(maps);
                return data + offset;
            }
        }
    }
    handle->next = (void*) -1;
    free(maps);
    return (void*) -1;
}


static inline uint8_t hextonib(char hex) {
    //hex &= 0xf;
    if(hex >= '0' && hex <= '9')
        return hex - '0';
    else if(hex >= 'a' && hex <= 'f')
        return hex - 'a' + 0xa;
    else if(hex >= 'A' && hex <= 'F')
        return hex - 'A' + 0xa;
    return 0;
}
ssize_t parse_sigpattern(const char *in_pattern,
    byte **sigbyte, byte **mask) {
    *sigbyte = malloc((strlen(in_pattern)/2)+1);
    *mask = malloc((strlen(in_pattern)/2)+1);
    if(!*sigbyte || !*mask) {
        // printf("malloc failed!");
        return -1;
    }
    memset(*sigbyte, 0, (strlen(in_pattern)/2)+1);
    memset(*mask, 0, (strlen(in_pattern)/2)+1);

    size_t head = 0;
    int nibble = 0;
    for(size_t i = 0; i < strlen(in_pattern); i++) {
        if(isxdigit(in_pattern[i])) {
            if(!nibble) {
                (*sigbyte)[head] |= hextonib(in_pattern[i]) << 4;
                (*mask)[head] |= 0xf << 4;
            } else {
                (*sigbyte)[head] |= hextonib(in_pattern[i]) & 0xf;
                (*mask)[head] |= 0xf;
            }
        }
        else if(in_pattern[i] == '?') {
            (*sigbyte)[head] |= 0;
            (*mask)[head] |= 0;
        }
        else if (in_pattern[i] == ' ') {
            continue;
        }
        else {
            // printf("not a good string!\n");
            free(*sigbyte);
            free(*mask);
            return -1;
        }
        if(nibble)
            head++;
        nibble = !nibble;
    }
    return head;
}
/*
// 1 byte simple precision scanner
size_t search_sigpattern(byte *data, size_t data_len,
    byte *sigbyte, byte *mask, size_t sig_len) {
    for(size_t i = 0; i <= (data_len - sig_len); i++) {
        for(size_t j = 0; j < sig_len; j++) {
            if((data[i+j] & mask[j]) != (sigbyte[j] & mask[j]))
                break;
            if(j+1 == sig_len) {
                return i;
            }
        }
    }
    return -1;
}
*/
// 4 byte aligned scanner (ARM)
size_t search_sigpattern4(uint32_t *data, size_t data_len,
    uint32_t *sigbyte, uint32_t *mask, size_t sig_len) {
    data_len /= 4;
    sig_len /= 4;
    for(size_t i = 0; i <= (data_len - sig_len); i++) {
        for(size_t j = 0; j < sig_len; j++) {
            if((data[i+j] & mask[j]) != (sigbyte[j] & mask[j]))
                break;
            if(j+1 == sig_len) {
                return i*4;
            }
        }
    }
    return -1;
}
// 1 byte hybrid precision scanner
size_t search_sigpattern_hybrid(byte *data, size_t data_len,
    byte *sigbyte, byte *mask, size_t sig_len) {
    for(size_t i = 0; i <= (data_len - sig_len); i++) {
        for(size_t j = 0; j < sig_len; j++) {
            if((sig_len - j) >= 8) {
#ifdef __LP64__
                // 8 byte alignment
                if(
                    (*(uint64_t*)((size_t)data + i + j) & *((uint64_t*)((size_t)mask + j)))
                    != (*(uint64_t*)((size_t)sigbyte + j) & *((uint64_t*)((size_t)mask + j)))
                )
                    break;
                j+=7;
            } else
#endif
            if((sig_len - j) >= 4) {
                // 4 byte alignment
                if(
                    (*(uint32_t*)((size_t)data + i + j) & *((uint32_t*)((size_t)mask + j)))
                    != (*(uint32_t*)((size_t)sigbyte + j) & *((int32_t*)((size_t)mask + j)))
                )
                    break;
                j+=3;
            } else {
                if((data[i+j] & mask[j]) != (sigbyte[j] & mask[j]))
                    break;
            }
            if(j+1 == sig_len) {
                return i;
            }
        }
    }
    return -1;
}
