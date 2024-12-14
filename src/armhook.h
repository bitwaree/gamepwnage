#include "mem.h"
// For 64 bit armhook: requires 28 bytes minimum
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook64(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len);

//For 32 bit armhook: requires 20 bytes minimum
uintptr_t __attribute__((visibility(VISIBILITY_FLAG))) arm_hook32(uintptr_t AddresstoHook, uintptr_t hookFunAddr, size_t len);
