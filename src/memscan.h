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

// flags
#define GPWN_SIGSCAN_XMEM       1
#define GPWN_SIGSCAN_WMEM       1 << 1
#define GPWN_SIGSCAN_FORCEMODE  1 << 3

/*
Note:
(*) If no flags are specified during setup, scanner will go through all readable
    memory regions. And if (GPWN_SIGSCAN_XMEM | GPWN_SIGSCAN_WMEM) used as flags,
    it will only scan memory regions with both read and write protections.
(*) If GPWN_SIGSCAN_FORCEMODE used, it will attempt overriding protection before
    reading.
*/
sigscan_handle *sigscan_setup(const char *pattern_str, const char *libname, int flags);
sigscan_handle *sigscan_setup_raw(byte *sigbyte, byte *mask, size_t sig_size, uintptr_t start_addr, uintptr_t end_addr, int flags);
void sigscan_cleanup(sigscan_handle *handle);

void *get_sigscan_result(sigscan_handle *handle);
