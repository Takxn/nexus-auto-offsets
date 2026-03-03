/*
 * memory.cpp - Kernel-mode memory operations
 *
 * R/W via physical memory reads (CR3 page table walk) to bypass EAC monitoring.
 * Alloc/Free/Protect via Zw* APIs.
 * Module base via PEB walker.
 */

#include "definitions.h"
#include "memory.h"
#include "physical_memory.h"

/* ── System Module Helpers ───────────────────────────────────────── */

PVOID GetSystemModuleBase(const char* moduleName)
{
    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bytes, 'mEmK');
    if (!modules) return NULL;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
        modules, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'mEmK');
        return NULL;
    }

    PVOID base = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        char* name = (char*)modules->Modules[i].FullPathName +
                     modules->Modules[i].OffsetToFileName;
        if (_stricmp(name, moduleName) == 0) {
            base = modules->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, 'mEmK');
    return base;
}

PVOID GetSystemModuleExport(const char* moduleName, LPCSTR routineName)
{
    PVOID base = GetSystemModuleBase(moduleName);
    if (!base) return NULL;
    return RtlFindExportedRoutineByName(base, routineName);
}

/* ── Write to Read-Only Memory ───────────────────────────────────── */

BOOL WriteReadOnlyMemory(void* address, void* buffer, size_t size)
{
    if (!address || !buffer || !size) return FALSE;

    PMDL mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
    if (!mdl) return FALSE;

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return FALSE;
    }

    NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
    if (NT_SUCCESS(status)) {
        memcpy(mapped, buffer, size);
    }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return NT_SUCCESS(status);
}

BOOL WriteMemory(void* address, void* buffer, size_t size)
{
    if (!address || !buffer) return FALSE;

    __try {
        RtlCopyMemory(address, buffer, size);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* ── Process Memory R/W ──────────────────────────────────────────── */

BOOL myReadProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size)
{
    if (!address || !buffer || !size) return FALSE;

    /* Use physical memory read to bypass EAC monitoring of MmCopyVirtualMemory */
    return PhysicalReadProcessMemory(
        pid,
        (ULONG64)address,
        buffer,
        (SIZE_T)size
    );
}

BOOL myWriteProcessMemory(HANDLE pid, PVOID address, PVOID buffer, DWORD size)
{
    if (!address || !buffer || !size) return FALSE;

    /* Use physical memory write to bypass EAC monitoring of MmCopyVirtualMemory */
    return PhysicalWriteProcessMemory(
        pid,
        (ULONG64)address,
        buffer,
        (SIZE_T)size
    );
}

/* ── Virtual Memory Management ───────────────────────────────────── */

PVOID AllocateVirtualMemory(HANDLE pid, ULONGLONG size, DWORD protect)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return NULL;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    PVOID base = NULL;
    SIZE_T regionSize = (SIZE_T)size;
    NTSTATUS status = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &base, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, protect);

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return NT_SUCCESS(status) ? base : NULL;
}

VOID FreeVirtualMemory(HANDLE pid, PVOID base)
{
    if (!base) return;

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    SIZE_T regionSize = 0;
    ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &regionSize, MEM_RELEASE);

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);
}

BOOL ProtectVirtualMemory(HANDLE pid, UINT_PTR base, ULONGLONG size, DWORD protection)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return FALSE;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    PVOID addr = (PVOID)base;
    SIZE_T regionSize = (SIZE_T)size;
    ULONG oldProtect = 0;
    NTSTATUS status = ZwProtectVirtualMemory(
        ZwCurrentProcess(), &addr, &regionSize, protection, &oldProtect);

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return NT_SUCCESS(status);
}

/* ── Process Handle ──────────────────────────────────────────────── */

PVOID GetProcessHandle(HANDLE pid)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return NULL;

    HANDLE hProcess = NULL;
    NTSTATUS status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType,
        KernelMode, &hProcess);

    ObfDereferenceObject(process);
    return NT_SUCCESS(status) ? (PVOID)hProcess : NULL;
}

/* ── Module Base via PEB Walk ────────────────────────────────────── */

PVOID GetProcessModuleBase(HANDLE pid, const wchar_t* moduleName)
{
    if (!moduleName) return NULL;

    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return NULL;

    /*
     * CRITICAL: moduleName points to usermode memory of the CALLING process.
     * After KeStackAttachProcess, the address space switches to the TARGET
     * process, making that pointer invalid. Copy to kernel stack first.
     */
    WCHAR nameBuffer[64] = { 0 };
    __try {
        wcsncpy(nameBuffer, moduleName, 63);
        nameBuffer[63] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ObfDereferenceObject(process);
        return NULL;
    }

    PVOID result = NULL;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    __try {
        PPEB_KM peb = PsGetProcessPeb(process);
        if (peb && peb->Ldr) {
            for (PLIST_ENTRY pEntry = peb->Ldr->ModuleListLoadOrder.Flink;
                 pEntry != &peb->Ldr->ModuleListLoadOrder;
                 pEntry = pEntry->Flink)
            {
                PLDR_DATA_TABLE_ENTRY_KM entry = CONTAINING_RECORD(
                    pEntry, LDR_DATA_TABLE_ENTRY_KM, InLoadOrderModuleList);

                if (entry->BaseDllName.Buffer) {
                    if (_wcsicmp(entry->BaseDllName.Buffer, nameBuffer) == 0) {
                        result = entry->DllBase;
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = NULL;
    }

    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);

    return result;
}
