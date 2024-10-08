/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include <Windows.h>

BOOL WritetoMemory(void *Dest, void *Src, size_t Size);
BOOL ReadfromMemory(void *Dest, void *Src, size_t Size);
DWORD PatchNop(void *Address, size_t len);
uintptr_t GetAddress(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset);
DWORD GetAddressEx(DWORD Baseaddr, DWORD offsets[], int TotalOffset, HANDLE hProcess);

bool HookAddress(void *AddresstoHook, void *hookFunAddr, size_t len);
