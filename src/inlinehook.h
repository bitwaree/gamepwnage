/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include "config.h"
#include <stdbool.h>

typedef struct {
    void *address;          // where to place hook
    void *fake;             // the fake function
    void *trampoline_addr;  // allocated address to place the copied bytes
    int flags;              // flags
} hook_handle;

#if defined(__aarch64__)
#define GPWN_AARCH64_LEGACYHOOK 0x1 /* 5 instructions, 20 bytes */
#define GPWN_AARCH64_MICROHOOK  0x2 /* 3 instructions, 12 bytes */
#define GPWN_AARCH64_NANOHOOK   0x3 /* 1 instructions, 4 bytes  */
#elif defined(__arm__)
#define GPWN_ARM_LEGACYHOOK     0x1 /* 3 instructions, 12 bytes */
#define GPWN_ARM_NANOHOOK       0x2 /* 1 instructions, 4 bytes  */
#endif

hook_handle* __attribute__((visibility(VISIBILITY_FLAG))) hook_addr(void *address, void *fake, void **original_func, int flags);
bool __attribute__((visibility(VISIBILITY_FLAG))) rm_hook(hook_handle *handle);
