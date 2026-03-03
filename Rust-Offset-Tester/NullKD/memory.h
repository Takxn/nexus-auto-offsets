#pragma once
/*
 * memory.h - Kernel-mode memory operation prototypes
 */

#include "definitions.h"

/* System module helpers */
PVOID GetSystemModuleBase(const char* moduleName);
PVOID GetSystemModuleExport(const char* moduleName, LPCSTR routineName);

/* Write to read-only kernel memory (for hooking) */
BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size);
BOOL WriteMemory(void* address, void* buffer, size_t size);

/* Process memory R/W */
BOOL myReadProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size);
BOOL myWriteProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size);

/* Virtual memory management */
PVOID AllocateVirtualMemory(HANDLE pid, ULONGLONG size, DWORD protect);
VOID  FreeVirtualMemory(HANDLE pid, PVOID base);
BOOL  ProtectVirtualMemory(HANDLE pid, UINT_PTR base, ULONGLONG size, DWORD protection);

/* Process handle */
PVOID GetProcessHandle(HANDLE pid);

/* Module base via PEB walk */
PVOID GetProcessModuleBase(HANDLE pid, const wchar_t* moduleName);