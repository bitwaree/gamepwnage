/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/


//#include "stdafx.h"
#include <stdint.h>
#include "mem.h"

BOOL WritetoMemory(void *Dest, void *Src, size_t Size)
{

	DWORD oldProtect;

	VirtualProtect(Dest, Size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(Dest, Src, Size);
	VirtualProtect(Dest, Size, oldProtect, &oldProtect);

	return TRUE;
}

BOOL ReadfromMemory(void *Dest, void *Src, size_t Size)
{

	DWORD oldProtect;

	VirtualProtect(Src, Size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(Dest, Src, Size);
	VirtualProtect(Src, Size, oldProtect, &oldProtect);

	return TRUE;
}

DWORD PatchNop(void *Address, size_t len)
{
	DWORD oldProtect, temp;

	VirtualProtect(Address, len, PAGE_EXECUTE_READWRITE, &oldProtect);
	memset(Address, 0x90, len);
	VirtualProtect(Address, len, oldProtect, &temp);

	return TRUE;
}

uintptr_t GetAddress(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
{

	int i = 0;
	uintptr_t Address = Baseaddr; // Get the base address from the parameters

	do
	{
		Address = *((uintptr_t *)Address); // Dereferance current address
		if (Address == NULL)
		{
			return 0;
		} // If address = NULL then return 0;

		Address += offsets[i]; // Address = Address + offset
		i++;

	} while (i < TotalOffset);

	return Address; // Return Final Address
}

DWORD GetAddressEx(DWORD Baseaddr, DWORD offsets[], int TotalOffset, HANDLE hProcess)
{

	int i = 0;
	DWORD Address = Baseaddr; // Get the base address from the parameters
	DWORD AddrBak = NULL;

	DWORD dwBytesRead = NULL;
	BOOL ifRead;

	do
	{
		AddrBak = Address;

		ifRead = ReadProcessMemory(hProcess, (LPVOID)AddrBak, &Address, sizeof(DWORD), (SIZE_T *)&dwBytesRead); // Dereferance current address
		if (Address == NULL || dwBytesRead != sizeof(DWORD) || ifRead == false)
		{
			return 0;
		} // If address = NULL then return 0;

		Address += offsets[i]; // Address = Address + offset
		i++;

	} while (i < TotalOffset);

	return Address; // Return Final Address
}

bool HookAddress(void *AddresstoHook, void *hookFunAddr, size_t len)
{
	if (len < 5)
	{
		return false;
	}
	// Change Permission
	DWORD oldProtection, tempProtection;
	VirtualProtect(AddresstoHook, len, PAGE_EXECUTE_READWRITE, &oldProtection);
	// patch nops
	memset(AddresstoHook, 0x90, len);

	uint32_t RelativeAddress = ((uintptr_t)hookFunAddr - ((uintptr_t)AddresstoHook + 5)); // get the relative address

	*(BYTE *)atHook = 0xE9;        // copy jmp instruction
	memcpy((void *)((uintptr_t)AddresstoHook + 1), &RelativeAddress, sizeof(uint32_t));
	// Restore the previous permisssion
	VirtualProtect(AddresstoHook, len, oldProtection, &tempProtection);
	return true;
}

