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
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>

#include "mem.h"
#include "proc.h"
#include "inlinehook.h"

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
#include "hook86.h"
#elif defined(__arm__) || defined (__aarch64__)
#include "armhook.h"
#endif

#ifdef __aarch64__
#define AARCH64_LEGACY_HOOKBYTES_LEN 20
#define AARCH64_MICRO_HOOKBYTES_LEN  12
#define AARCH64_NANO_HOOKBYTES_LEN    4
#define MAX_BUFFERLEN AARCH64_LEGACY_HOOKBYTES_LEN

static inline uint32_t encode_adrp(int64_t offset) {
    // 32 bits signed
    if(offset <= -((int64_t)1 << 32) ||
        offset >= (((int64_t)1 << 32) - 1))
        return 0; // out of range
    // page number 4K
    int64_t page_offset = offset >> 12;
    // immlo (bits [30:29] in instruction)
    uint32_t immlo = (page_offset & 0x3) << 29;
    // extract immhi (bits [23:5] in instruction)
    uint32_t immhi = ((page_offset >> 2) & 0x7FFFF) << 5;
    // ADRP base opcode: 1 00 10000 (fixed bits)
    uint32_t base_opcode = 0x90000000;
    // assemble : base_opcode + immhi + immlo + Rd
    return base_opcode | immhi | immlo | 17;
}
static inline uint32_t encode_b(int32_t offset) {
    // 26 bits signed
    if(offset < -((int32_t)1 << 27) ||
        offset >= ((int32_t)1 << 27))
        return 0; // out of range
    // convert offset to 26-bit immediate (divide by 4)
    int32_t imm26 = (int32_t)(offset >> 2);
    // mask to 26 bits (ensures proper handling of negative values)
    uint32_t imm26_masked = (uint32_t)imm26 & 0x03FFFFFF;
    // B instruction opcode: 000101 (fixed bits)
    return 0x14000000 | imm26_masked;
}
#elif defined(__arm__)
#define ARM_LEGACY_HOOKBYTES_LEN 12
#define ARM_NANO_HOOKBYTES_LEN    4
#define MAX_BUFFERLEN ARM_LEGACY_HOOKBYTES_LEN

static inline uint32_t encode_b(int32_t offset) {
    // calculate the offset in words (divide by 4)
    int32_t word_offset = (offset - 8) >> 2;
    if (word_offset < -0x800000 || word_offset > 0x7FFFFF)
        return 0; // out of range
    // mask to 24 bits (signed)
    word_offset &= 0x00FFFFFF;
    return 0xEA000000 | word_offset;
}
#endif

GPWNAPI hook_handle* hook_addr(void *address, void *fake, void **original_func, int flags) {
    hook_handle *handle = malloc(sizeof(hook_handle));
    if(!handle) {
        // perror("malloc() failed.");
        return 0;
    }
    handle->address = address;
    handle->fake = fake;
    handle->flags = 0;
    size_t page_size = (size_t) sysconf(_SC_PAGESIZE);
    void *aligned_addr = (void*) ((uintptr_t) address & ~(page_size - 1));
    // allocate the trampoline
    handle->trampoline_addr = mmap_near(aligned_addr, page_size, PROT_EXEC | PROT_READ);
    if(handle->trampoline_addr == MAP_FAILED) {
        // perror("mmap() failed.");
        free(handle);
        return 0;
    }
    // read the bytes
    uint8_t mem_buffer[MAX_BUFFERLEN];
    if(!read_mem(mem_buffer, address, MAX_BUFFERLEN)) {
        // fputs("read_mem() failed.\n", stderr);
        munmap(handle->trampoline_addr, page_size);
        free(handle);
        return 0;
    }
#ifdef __aarch64__
    if(
        (handle->trampoline_addr - address) >= -(1 << 27) &&
        (handle->trampoline_addr - address) < ((1 << 27) - 1) &&
        (!flags || (flags & GPWN_AARCH64_NANOHOOK) == GPWN_AARCH64_NANOHOOK)
    ) {
        // nano hook
        if(!arm_hook64((uintptr_t) handle->trampoline_addr, (uintptr_t) fake,
                AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN,
                mem_buffer, AARCH64_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!arm_hook64( (uintptr_t)(handle->trampoline_addr +
                AARCH64_LEGACY_HOOKBYTES_LEN + AARCH64_NANO_HOOKBYTES_LEN),
            (uintptr_t) (address + AARCH64_NANO_HOOKBYTES_LEN),
            AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        uint32_t b_opcode = encode_b(handle->trampoline_addr - address);
        if(!write_mem(address, &b_opcode, 4)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_AARCH64_NANOHOOK;
        *original_func = handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN;
        return handle;
    }
    if (
        (handle->trampoline_addr - address) >= -((int64_t)1 << 32) &&
        (handle->trampoline_addr - address) < (((int64_t)1 << 32) - 1) &&
        !flags || (flags & GPWN_AARCH64_MICROHOOK) == GPWN_AARCH64_MICROHOOK
    ) {
        // micro hook
        uint32_t hook_bytes[3];
        hook_bytes[0] = encode_adrp(((int64_t)handle->trampoline_addr & ~((int64_t)0xfff))
        - ((int64_t) address &  ~((int64_t)0xfff)));
        hook_bytes[1] = 0xf9400231;
        hook_bytes[2] = 0xd61f0220;
        if(!write_mem(handle->trampoline_addr, &fake, 8)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr + 8, mem_buffer,
                AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!arm_hook64(
            (uintptr_t) (handle->trampoline_addr + 8 + AARCH64_MICRO_HOOKBYTES_LEN),
            (uintptr_t) (address + AARCH64_MICRO_HOOKBYTES_LEN),
            AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(address, &hook_bytes, AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_AARCH64_MICROHOOK;
        *original_func = handle->trampoline_addr + 8;
        return handle;
    }
    if ((!flags || (flags & GPWN_AARCH64_LEGACYHOOK) == GPWN_AARCH64_LEGACYHOOK)) {
        // legacy hook
        if (!write_mem(handle->trampoline_addr,
                mem_buffer, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm_hook64(
            (uintptr_t)(handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN),
            (uintptr_t)(address + AARCH64_LEGACY_HOOKBYTES_LEN),
            AARCH64_LEGACY_HOOKBYTES_LEN)
        ) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm_hook64((uintptr_t)address,
                (uintptr_t)fake, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_AARCH64_LEGACYHOOK;
        *original_func = handle->trampoline_addr;
        return handle;
    }
#elif defined(__arm__)
    if(
        (handle->trampoline_addr - address) >= -(1 << 27) &&
        (handle->trampoline_addr - address) < ((1 << 27) - 1) &&
        (!flags || (flags & GPWN_ARM_NANOHOOK) == GPWN_ARM_NANOHOOK)
    ) {
        // nano hook
        if(!arm_hook32((uintptr_t) handle->trampoline_addr, (uintptr_t) fake,
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if(!write_mem(handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN,
                mem_buffer, ARM_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm_hook32((uintptr_t)(handle->trampoline_addr +
                ARM_LEGACY_HOOKBYTES_LEN + ARM_NANO_HOOKBYTES_LEN),
                (uintptr_t)(address + ARM_NANO_HOOKBYTES_LEN),
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook64() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        uint32_t b_opcode = encode_b(handle->trampoline_addr - address);
        if(!write_mem(address, &b_opcode, 4)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_ARM_NANOHOOK;
        *original_func = handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN;
        return handle;
    }
    if ((!flags || (flags & GPWN_ARM_LEGACYHOOK) == GPWN_ARM_LEGACYHOOK)) {
        if(!write_mem(handle->trampoline_addr,
                mem_buffer, ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm_hook32(
                (uintptr_t)handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN,
                (uintptr_t)address + ARM_LEGACY_HOOKBYTES_LEN,
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook32() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        if (!arm_hook32((uintptr_t)address, (uintptr_t)fake,
                ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("arm_hook32() failed.\n", stderr);
            munmap(handle->trampoline_addr, page_size);
            free(handle);
            return 0;
        }
        handle->flags |= GPWN_ARM_LEGACYHOOK;
        *original_func = handle->trampoline_addr;
        return handle;
    }
#endif
    munmap(handle->trampoline_addr, page_size);
    free(handle);
    return 0;
}

GPWNAPI bool rm_hook(hook_handle *handle) {
    if(!handle) {
        return 0;
    }
    uint8_t mem_buffer[MAX_BUFFERLEN];
#ifdef __aarch64__
    if((handle->flags & GPWN_AARCH64_NANOHOOK) == GPWN_AARCH64_NANOHOOK) {
        if(!read_mem(mem_buffer,
            handle->trampoline_addr + AARCH64_LEGACY_HOOKBYTES_LEN,
            AARCH64_NANO_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, AARCH64_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
    else if((handle->flags & GPWN_AARCH64_MICROHOOK) == GPWN_AARCH64_MICROHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr + 8, AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, AARCH64_MICRO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
    else if((handle->flags & GPWN_AARCH64_LEGACYHOOK) == GPWN_AARCH64_LEGACYHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, AARCH64_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
#elif defined(__arm__)
    if((handle->flags & GPWN_ARM_NANOHOOK) == GPWN_ARM_NANOHOOK) {
        if(!read_mem(mem_buffer,
            handle->trampoline_addr + ARM_LEGACY_HOOKBYTES_LEN,
            ARM_NANO_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, ARM_NANO_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
    else if((handle->flags & GPWN_ARM_LEGACYHOOK) == GPWN_ARM_LEGACYHOOK) {
        if(!read_mem(mem_buffer, handle->trampoline_addr, ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("read_mem() failed.\n", stderr);
            return 0;
        }
        if(!write_mem(handle->address, mem_buffer, ARM_LEGACY_HOOKBYTES_LEN)) {
            // fputs("write_mem() failed.\n", stderr);
            return 0;
        }
    }
#endif
    munmap(handle->trampoline_addr, sysconf(_SC_PAGESIZE));
    free(handle);
    return 1;
}
