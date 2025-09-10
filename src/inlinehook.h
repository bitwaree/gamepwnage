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
} hook_handle;

hook_handle* __attribute__((visibility(VISIBILITY_FLAG))) hook_addr(void *address, void *fake, void **original_func);
bool __attribute__((visibility(VISIBILITY_FLAG))) rm_hook(hook_handle *handle);
