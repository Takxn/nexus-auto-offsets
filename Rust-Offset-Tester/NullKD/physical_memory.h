/*
 * physical_memory.h - Physical memory R/W via CR3 page table walk
 *
 * Bypasses MmCopyVirtualMemory monitoring by EAC.
 * Uses MmCopyMemory (physical) for reads, MmMapIoSpace for writes.
 *
 * Based on UC research (Dec 2025 / Jan 2026):
 *   - CR3 via KeStackAttachProcess + __readcr3() with aggressive caching
 *   - EPROCESS+0x28 (DirectoryTableBase) is encrypted/stripped by EAC
 *   - MmCopyMemory with MM_COPY_MEMORY_PHYSICAL is safest read method
 */

#pragma once
#include "definitions.h"
#include "spoof_call.h"
#include <intrin.h>

/* ── Page Table Constants ────────────────────────────────────────── */

#define PTE_PRESENT      0x1ULL
#define PTE_LARGE_PAGE   0x80ULL
#define PTE_PHYS_MASK    0x0000FFFFFFFFF000ULL
#define PAGE_OFFSET_MASK 0xFFFULL

/* ── CR3 Cache ───────────────────────────────────────────────────── */

typedef struct _CR3_CACHE_ENTRY {
    volatile ULONG64 cr3;
    volatile HANDLE  pid;
    volatile ULONG   callCount;
    volatile BOOLEAN validated;
} CR3_CACHE_ENTRY;

static CR3_CACHE_ENTRY g_Cr3Cache = { 0, 0, 0, FALSE };

/* Minimum attach calls before caching (EAC may trash CR3 early) */
#define CR3_CACHE_THRESHOLD  500

/* ── CR3 Validation ──────────────────────────────────────────────── */
/*
 * Validate a CR3 by reading self-referencing PML4 entry.
 * A valid CR3 should have the PML4 page present and readable.
 */
static BOOLEAN ValidateCR3(ULONG64 cr3)
{
    if (cr3 == 0 || (cr3 & 0xFFF) != 0)
        return FALSE;  /* Must be page-aligned and non-zero */

    /* Try to read the first PML4 entry */
    ULONG64 pml4e = 0;
    MM_COPY_ADDRESS addr;
    addr.PhysicalAddress.QuadPart = (LONGLONG)(cr3 & PTE_PHYS_MASK);
    SIZE_T bytesRead = 0;

    NTSTATUS status = MmCopyMemory(&pml4e, addr, sizeof(pml4e),
        MM_COPY_MEMORY_PHYSICAL, &bytesRead);

    if (!NT_SUCCESS(status) || bytesRead != sizeof(pml4e))
        return FALSE;

    /* At least one PML4 entry should be present (usermode pages exist) */
    return (pml4e & PTE_PRESENT) != 0;
}

/* ── Get Process CR3 ─────────────────────────────────────────────── */

static ULONG64 GetProcessCR3(HANDLE pid)
{
    if (!pid) return 0;

    /* Check cache */
    if (g_Cr3Cache.pid == pid && g_Cr3Cache.validated && g_Cr3Cache.cr3)
        return g_Cr3Cache.cr3;

    /* Reset cache if PID changed */
    if (g_Cr3Cache.pid != pid) {
        g_Cr3Cache.pid = pid;
        g_Cr3Cache.callCount = 0;
        g_Cr3Cache.cr3 = 0;
        g_Cr3Cache.validated = FALSE;
    }

    g_Cr3Cache.callCount++;

    /* Get EPROCESS */
    PEPROCESS process = NULL;
    NTSTATUS lookupStatus;
    if (g_SpoofStub)
        lookupStatus = SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        lookupStatus = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(lookupStatus))
        return 0;

    /* Attach and read actual CR3 from hardware register */
    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    ULONG64 cr3 = __readcr3();

    if (g_SpoofStub)
        SpoofCall1(KeUnstackDetachProcess, &apc);
    else
        KeUnstackDetachProcess(&apc);

    if (g_SpoofStub)
        SpoofCall1(ObfDereferenceObject, process);
    else
        ObfDereferenceObject(process);

    /* Validate and cache after threshold */
    if (cr3 && ValidateCR3(cr3)) {
        g_Cr3Cache.cr3 = cr3;
        if (g_Cr3Cache.callCount >= CR3_CACHE_THRESHOLD)
            g_Cr3Cache.validated = TRUE;
    }

    return cr3;
}

/* ── Read Physical Memory ────────────────────────────────────────── */

static NTSTATUS ReadPhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || !physAddr)
        return STATUS_INVALID_PARAMETER;

    MM_COPY_ADDRESS addr;
    addr.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    SIZE_T bytesRead = 0;

    return MmCopyMemory(buffer, addr, size,
        MM_COPY_MEMORY_PHYSICAL, &bytesRead);
}

/* ── Write Physical Memory ───────────────────────────────────────── */

static NTSTATUS WritePhysicalAddress(ULONG64 physAddr, PVOID buffer, SIZE_T size)
{
    if (!buffer || !size || !physAddr)
        return STATUS_INVALID_PARAMETER;

    /* Map the physical page into kernel virtual address space */
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)physAddr;

    PVOID mapped = MmMapIoSpace(pa, size, MmNonCached);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* Copy data to physical memory */
    memcpy(mapped, buffer, size);

    MmUnmapIoSpace(mapped, size);
    return STATUS_SUCCESS;
}

/* ── 4-Level Page Table Walk ─────────────────────────────────────── */

static ULONG64 TranslateVirtualAddress(ULONG64 cr3, ULONG64 virtualAddress)
{
    if (!cr3 || !virtualAddress)
        return 0;

    ULONG64 pml4_idx = (virtualAddress >> 39) & 0x1FF;
    ULONG64 pdpt_idx = (virtualAddress >> 30) & 0x1FF;
    ULONG64 pd_idx   = (virtualAddress >> 21) & 0x1FF;
    ULONG64 pt_idx   = (virtualAddress >> 12) & 0x1FF;
    ULONG64 offset   = virtualAddress & PAGE_OFFSET_MASK;

    ULONG64 pte = 0;

    /* PML4 → PDPT pointer */
    if (!NT_SUCCESS(ReadPhysicalAddress(
            (cr3 & PTE_PHYS_MASK) + pml4_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    /* PDPT → PD pointer (check 1GB large page) */
    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pdpt_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)  /* 1GB page */
        return (pte & 0xFFFFC0000000ULL) + (virtualAddress & 0x3FFFFFFFULL);

    /* PD → PT pointer (check 2MB large page) */
    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pd_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)  /* 2MB page */
        return (pte & 0xFFFFFE00000ULL) + (virtualAddress & 0x1FFFFFULL);

    /* PT → Physical address (4KB page) */
    if (!NT_SUCCESS(ReadPhysicalAddress(
            (pte & PTE_PHYS_MASK) + pt_idx * 8, &pte, 8)))
        return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    return (pte & PTE_PHYS_MASK) + offset;
}

/* ── High-Level Physical R/W (handles page boundaries + usermode buffers) ─ */

/*
 * IMPORTANT: MmCopyMemory writes to a KERNEL buffer, not directly to usermode.
 * We must use an intermediate kernel buffer, then copy to/from the usermode
 * buffer that the client provided.
 */

#define PHYS_STACK_BUF_SIZE  0x1000  /* 4KB stack buffer for small ops */

static BOOL PhysicalReadProcessMemory(
    HANDLE pid, ULONG64 virtualAddress, PVOID userBuffer, SIZE_T size)
{
    if (!userBuffer || !size || !virtualAddress)
        return FALSE;

    ULONG64 cr3 = GetProcessCR3(pid);
    if (!cr3) return FALSE;

    /* Allocate kernel intermediate buffer */
    BOOLEAN usePool = (size > PHYS_STACK_BUF_SIZE);
    PUCHAR kernelBuf = NULL;

    if (usePool) {
        kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'rPhM');
        if (!kernelBuf) return FALSE;
    } else {
        /* Use stack allocation for small reads (faster, no pool overhead) */
        kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'rPhM');
        if (!kernelBuf) return FALSE;
    }

    RtlZeroMemory(kernelBuf, size);

    BOOL success = TRUE;
    SIZE_T totalRead = 0;

    while (totalRead < size)
    {
        ULONG64 currentVA = virtualAddress + totalRead;
        SIZE_T pageRemaining = 0x1000 - (currentVA & PAGE_OFFSET_MASK);
        SIZE_T chunkSize = min(pageRemaining, size - totalRead);

        ULONG64 physAddr = TranslateVirtualAddress(cr3, currentVA);
        if (!physAddr) {
            success = FALSE;
            break;
        }

        if (!NT_SUCCESS(ReadPhysicalAddress(physAddr, kernelBuf + totalRead, chunkSize))) {
            success = FALSE;
            break;
        }

        totalRead += chunkSize;
    }

    /* Copy from kernel buffer to usermode buffer */
    if (success) {
        __try {
            RtlCopyMemory(userBuffer, kernelBuf, size);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            success = FALSE;
        }
    }

    ExFreePoolWithTag(kernelBuf, 'rPhM');
    return success;
}

static BOOL PhysicalWriteProcessMemory(
    HANDLE pid, ULONG64 virtualAddress, PVOID userBuffer, SIZE_T size)
{
    if (!userBuffer || !size || !virtualAddress)
        return FALSE;

    /*
     * Strategy: Use KeStackAttachProcess + direct write for writes.
     *
     * Why not physical write (MmMapIoSpace)?
     *   - Demand-zero pages (freshly allocated) have no physical backing yet
     *   - MmMapIoSpace is designed for device MMIO, not regular RAM
     *   - Page table walk can't find uncommitted/transition PTEs
     *
     * Why is virtual write OK for EAC?
     *   - EAC primarily monitors cross-process READS (MmCopyVirtualMemory)
     *   - Writes are less scrutinized because cheats need to READ game memory
     *   - KeStackAttachProcess + direct copy doesn't trigger MmCopyVirtualMemory hooks
     */

    /* Copy from usermode to kernel buffer first */
    PUCHAR kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'wPhM');
    if (!kernelBuf) return FALSE;

    __try {
        RtlCopyMemory(kernelBuf, userBuffer, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(kernelBuf, 'wPhM');
        return FALSE;
    }

    PEPROCESS process = NULL;
    NTSTATUS lookupSt;
    if (g_SpoofStub)
        lookupSt = SpoofCall2(PsLookupProcessByProcessId, pid, &process);
    else
        lookupSt = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(lookupSt)) {
        ExFreePoolWithTag(kernelBuf, 'wPhM');
        return FALSE;
    }

    BOOL success = FALSE;
    KAPC_STATE apc;
    if (g_SpoofStub)
        SpoofCall2(KeStackAttachProcess, process, &apc);
    else
        KeStackAttachProcess(process, &apc);

    __try {
        RtlCopyMemory((PVOID)virtualAddress, kernelBuf, size);
        success = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        success = FALSE;
    }

    if (g_SpoofStub) {
        SpoofCall1(KeUnstackDetachProcess, &apc);
        SpoofCall1(ObfDereferenceObject, process);
    } else {
        KeUnstackDetachProcess(&apc);
        ObfDereferenceObject(process);
    }
    ExFreePoolWithTag(kernelBuf, 'wPhM');

    return success;
}
