#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/uio.h>

typedef unsigned char byte;
struct _memrange {
    void *start;
    void *end;
};
typedef struct {
    int flags;                // flags
    void *next;               // next address
    size_t sig_size;          // signature length
    byte* sig;                // signature bytes
    byte* mask;               // mask bytes
    struct _memrange memrange;    // explicit range (overrides other options)
    char *libname;            // library name
} sigscan_handle;

sigscan_handle *sigscan_setup(const char *pattern_str, const char *libname, int flags);
sigscan_handle *sigscan_setup_raw(byte *sigbyte, byte *mask, size_t sig_size, uintptr_t start_addr, uintptr_t end_addr, int flags);
void sigscan_cleanup(sigscan_handle *handle);

void *get_sigscan_result(sigscan_handle *handle);
