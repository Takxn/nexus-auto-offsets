#pragma once
/*
 * cleaner.h - Trace cleaning for kdmapper + driver object hiding
 *
 * Cleans:
 *   1. PiDDBCacheTable  - removes vulnerable driver load record
 *   2. MmUnloadedDrivers - removes unloaded driver entries
 *   3. Driver object     - NULLs DriverObject fields to prevent enumeration
 *
 * All pattern signatures target Windows 10/11 x64 (22H2+).
 */

#include "definitions.h"

/* ── Globals ─────────────────────────────────────────────────────── */

static PVOID  g_KernelBase = NULL;
static ULONG  g_KernelSize = 0;

/* ── Utility: Resolve RIP-relative address ───────────────────────── */

static PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    return (PVOID)(Instr + InstructionSize + RipOffset);
}

/* ── Utility: Pattern scan ───────────────────────────────────────── */

static NTSTATUS PatternScan(
    const UCHAR* pattern, UCHAR wildcard, ULONG_PTR len,
    const void* base, ULONG_PTR size, PVOID* ppFound)
{
    if (!ppFound || !pattern || !base) return STATUS_INVALID_PARAMETER;

    for (ULONG_PTR i = 0; i < size - len; i++) {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++) {
            if (pattern[j] != wildcard && pattern[j] != ((const UCHAR*)base)[i + j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

/* ── Get ntoskrnl base ───────────────────────────────────────────── */

static PVOID GetKernelBase(PULONG pSize)
{
    if (g_KernelBase) {
        if (pSize) *pSize = g_KernelSize;
        return g_KernelBase;
    }

    UNICODE_STRING routineName;
    RtlUnicodeStringInit(&routineName, L"NtOpenFile");
    PVOID checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (!checkPtr) return NULL;

    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0) return NULL;

    PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bytes, 'cLnK');
    if (!pMods) return NULL;
    RtlZeroMemory(pMods, bytes);

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
            if (checkPtr >= pMods->Modules[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMods->Modules[i].ImageBase + pMods->Modules[i].ImageSize))
            {
                g_KernelBase = pMods->Modules[i].ImageBase;
                g_KernelSize = pMods->Modules[i].ImageSize;
                if (pSize) *pSize = g_KernelSize;
                break;
            }
        }
    }
    ExFreePoolWithTag(pMods, 'cLnK');
    return g_KernelBase;
}

/* ── Scan a PE section in ntoskrnl ───────────────────────────────── */

static NTSTATUS ScanSection(
    const char* section, const UCHAR* pattern, UCHAR wildcard,
    ULONG_PTR len, PVOID* ppFound)
{
    if (!ppFound) return STATUS_INVALID_PARAMETER;

    PVOID base = GetKernelBase(NULL);
    if (!base) return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
    if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSection;
         pSec < pFirstSection + pHdr->FileHeader.NumberOfSections; pSec++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0) {
            PVOID ptr = NULL;
            NTSTATUS st = PatternScan(pattern, wildcard, len,
                (PUCHAR)base + pSec->VirtualAddress, pSec->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(st))
                *(PULONG_PTR)ppFound = (ULONG_PTR)ptr - (ULONG_PTR)base;
            return st;
        }
    }
    return STATUS_NOT_FOUND;
}

/* ══════════════════════════════════════════════════════════════════ */
/*  1. PiDDB Cache Table Cleaner                                    */
/* ══════════════════════════════════════════════════════════════════ */

static BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
    UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
    UCHAR PiDTablePtr_sig[]  = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

    PVOID PiDDBLockPtr = NULL;
    if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtr_sig, 0xCC,
        sizeof(PiDDBLockPtr_sig) - 1, &PiDDBLockPtr)))
        return FALSE;

    PVOID PiDTablePtr = NULL;
    if (!NT_SUCCESS(ScanSection("PAGE", PiDTablePtr_sig, 0xCC,
        sizeof(PiDTablePtr_sig) - 1, &PiDTablePtr)))
        return FALSE;

    UINT64 realLock  = (UINT64)g_KernelBase + (UINT64)PiDDBLockPtr;
    UINT64 realTable = (UINT64)g_KernelBase + (UINT64)PiDTablePtr;

    *lock  = (PERESOURCE)ResolveRelativeAddress((PVOID)realLock, 3, 7);
    *table = (PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)realTable, 3, 7);
    return TRUE;
}

static BOOLEAN CleanPiDDBCacheTable()
{
    PERESOURCE PiDDBLock = NULL;
    PRTL_AVL_TABLE PiDDBCacheTable = NULL;

    if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable))
        return FALSE;
    if (!PiDDBLock || !PiDDBCacheTable)
        return FALSE;

    /* Remove iqvw64e.sys entry (Intel driver used by kdmapper) */
    PIDCacheobj lookupEntry;
    UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
    lookupEntry.DriverName = driverName;
    lookupEntry.TimeDateStamp = 0x5284EAC3;

    ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

    PIDCacheobj* pFound = (PIDCacheobj*)RtlLookupElementGenericTableAvl(
        PiDDBCacheTable, &lookupEntry);
    if (pFound) {
        RemoveEntryList(&pFound->List);
        RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFound);
    }

    ExReleaseResourceLite(PiDDBLock);
    return (pFound != NULL);
}

/* ══════════════════════════════════════════════════════════════════ */
/*  2. MmUnloadedDrivers Cleaner                                    */
/* ══════════════════════════════════════════════════════════════════ */

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING  Name;
    PVOID           ModuleStart;
    PVOID           ModuleEnd;
    LARGE_INTEGER   UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

static BOOLEAN CleanMmUnloadedDrivers()
{
    /* Signature for MmUnloadedDrivers pointer in ntoskrnl PAGE section */
    UCHAR sig[] = "\x4C\x8B\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xC9\x4D\x85\xCC\x74";
    PVOID offset = NULL;

    if (!NT_SUCCESS(ScanSection("PAGE", sig, 0xCC, sizeof(sig) - 1, &offset)))
        return FALSE;

    UINT64 realAddr = (UINT64)g_KernelBase + (UINT64)offset;
    PMM_UNLOADED_DRIVER* pMmUnloadedDrivers =
        (PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)realAddr, 3, 7);

    if (!pMmUnloadedDrivers || !*pMmUnloadedDrivers)
        return FALSE;

    /* Clear name of iqvw64e.sys from unloaded drivers list */
    PMM_UNLOADED_DRIVER drivers = *pMmUnloadedDrivers;
    BOOLEAN cleaned = FALSE;

    for (int i = 0; i < 50; i++) {  /* Max 50 entries */
        if (drivers[i].Name.Buffer == NULL)
            continue;

        /* Check if it's the Intel driver */
        if (wcsstr(drivers[i].Name.Buffer, L"iqvw64e") ||
            wcsstr(drivers[i].Name.Buffer, L"Iqvw64e"))
        {
            /* Zero out the entry */
            RtlZeroMemory(drivers[i].Name.Buffer, drivers[i].Name.MaximumLength);
            RtlZeroMemory(&drivers[i], sizeof(MM_UNLOADED_DRIVER));
            cleaned = TRUE;
        }
    }

    return cleaned;
}

/* ══════════════════════════════════════════════════════════════════ */
/*  3. Driver Object Hiding                                         */
/* ══════════════════════════════════════════════════════════════════ */

/*
 * Removes all traces of the driver object:
 *   - Clears DriverName
 *   - NULLs DriverSection (LDR entry)
 *   - NULLs DriverStart/DriverSize
 *   - NULLs DriverInit
 *   - Clears all MajorFunction pointers
 *   - Erases PE headers at DriverStart
 */
static VOID HideDriverObject(PDRIVER_OBJECT DriverObject)
{
    if (!DriverObject) return;

    /* Clear driver name */
    if (DriverObject->DriverName.Buffer) {
        RtlZeroMemory(DriverObject->DriverName.Buffer,
            DriverObject->DriverName.MaximumLength);
        DriverObject->DriverName.Length = 0;
    }

    /* Unlink from PsLoadedModuleList */
    if (DriverObject->DriverSection) {
        PLIST_ENTRY entry = (PLIST_ENTRY)DriverObject->DriverSection;
        PLIST_ENTRY prev = entry->Blink;
        PLIST_ENTRY next = entry->Flink;
        if (prev && next) {
            prev->Flink = next;
            next->Blink = prev;
            entry->Flink = entry;
            entry->Blink = entry;
        }
    }

    /* Erase PE headers */
    __try {
        if (DriverObject->DriverStart) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(
                    (UCHAR*)DriverObject->DriverStart + dos->e_lfanew);
                ULONG headerSize = nt->OptionalHeader.SizeOfHeaders;
                if (headerSize == 0 || headerSize > PAGE_SIZE)
                    headerSize = PAGE_SIZE;
                RtlZeroMemory(DriverObject->DriverStart, headerSize);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    /* NULL out remaining fields */
    DriverObject->DriverSection = NULL;
    DriverObject->DriverInit = NULL;
    DriverObject->DriverStart = NULL;
    DriverObject->DriverSize = 0;

    /* Clear all MajorFunction pointers */
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NULL;
    }
}

/* ══════════════════════════════════════════════════════════════════ */
/*  Master Cleaner — call from DriverEntry                          */
/* ══════════════════════════════════════════════════════════════════ */

static BOOLEAN CleanAllTraces(PDRIVER_OBJECT DriverObject)
{
    BOOLEAN ok = TRUE;

    /* 1. Clean PiDDB cache */
    if (!CleanPiDDBCacheTable())
        ok = FALSE;

    /* 2. Clean MmUnloadedDrivers */
    CleanMmUnloadedDrivers();  /* non-fatal if fails */

    /* 3. Hide driver object */
    HideDriverObject(DriverObject);

    return ok;
}
