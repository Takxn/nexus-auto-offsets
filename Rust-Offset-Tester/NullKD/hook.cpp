/*
 * hook.cpp - dxgkrnl.sys hook installation and command dispatcher
 *
 * Uses PTE-based hooking for EAC integrity bypass:
 *   - Allocates a copy of the dxgkrnl page containing the target function
 *   - Applies the trampoline to the COPY
 *   - Swaps the PTE to point to the copy
 *   - Original physical page stays clean for integrity checks
 *
 * Usermode sends commands by calling the hooked function with a
 * REQUEST_DATA struct as the first parameter.
 */

#include "hook.h"
#include "pte_hook.h"
#include "spoof_call.h"
#include "physical_memory.h"

/* ── Hook Installation (PTE-based) ───────────────────────────────── */

BOOL Hook::Install(void* handlerAddr)
{
    if (!handlerAddr)
        return FALSE;

    /* Find the target function in dxgkrnl */
    PVOID hookTarget = GetSystemModuleExport(
        "dxgkrnl.sys",
        "NtQueryCompositionSurfaceStatistics"
    );

    if (!hookTarget)
        return FALSE;

    /* Init return address spoofing (find ntoskrnl gadgets) */
    InitSpoofCall();

    /*
     * Use PTE-based hook: the original dxgkrnl page stays unmodified.
     * A copy of the page with our trampoline is swapped in via PTE.
     * EAC integrity checks that read the original physical page see
     * clean, unmodified code.
     */
    if (InstallPteHook(hookTarget, handlerAddr))
        return TRUE;

    /*
     * Fallback: direct code patch if PTE hook fails.
     * This is less stealthy but ensures the driver still works.
     * Possible PTE hook failure reasons:
     *   - PTE base pattern not found (unusual Windows version)
     *   - Contiguous memory allocation failed
     *   - PTE not present or large page
     */
    BYTE patch[12] = { 0 };
    patch[0] = 0x48;  /* REX.W prefix */
    patch[1] = 0xB8;  /* MOV RAX, imm64 */
    uintptr_t addr = reinterpret_cast<uintptr_t>(handlerAddr);
    memcpy(&patch[2], &addr, sizeof(void*));
    patch[10] = 0xFF; /* JMP RAX */
    patch[11] = 0xE0;

    WriteReadOnlyMemory(hookTarget, patch, sizeof(patch));

    return TRUE;
}

/* ── Hook Handler ────────────────────────────────────────────────── */

NTSTATUS Hook::Handler(PVOID callParam)
{
    /* Validate pointer */
    if (!callParam || !MmIsAddressValid(callParam))
        return STATUS_SUCCESS;

    PREQUEST_DATA req = (PREQUEST_DATA)callParam;

    /* Check magic to distinguish our calls from legitimate ones */
    if (req->magic != REQUEST_MAGIC)
        return STATUS_SUCCESS;

    switch (req->command) {

    /* ─── Physical Memory R/W (EAC-safe) ─────────────────────────── */

    case CMD_READ:
        req->result = PhysicalReadProcessMemory(
            (HANDLE)req->pid,
            req->address,
            (PVOID)req->buffer,
            (SIZE_T)req->size
        ) ? 1 : 0;
        break;

    case CMD_WRITE:
        req->result = PhysicalWriteProcessMemory(
            (HANDLE)req->pid,
            req->address,
            (PVOID)req->buffer,
            (SIZE_T)req->size
        ) ? 1 : 0;
        break;

    /* ─── Virtual Memory R/W (fallback, uses MmCopyVirtualMemory) ── */

    case CMD_READ64:
        myReadProcessMemory(
            (HANDLE)req->pid,
            (PVOID)req->address,
            (PVOID)req->buffer,
            (DWORD)req->size
        );
        break;

    case CMD_WRITE64:
        myWriteProcessMemory(
            (HANDLE)req->pid,
            (PVOID)req->address,
            (PVOID)req->buffer,
            (DWORD)req->size
        );
        break;

    /* ─── Module / Process Operations ────────────────────────────── */

    case CMD_MODULE_BASE:
        req->result = (unsigned __int64)GetProcessModuleBase(
            (HANDLE)req->pid,
            req->module_name
        );
        break;

    case CMD_ALLOC:
        req->result = (unsigned __int64)AllocateVirtualMemory(
            (HANDLE)req->pid,
            req->size,
            req->protect
        );
        break;

    case CMD_FREE:
        FreeVirtualMemory(
            (HANDLE)req->pid,
            (PVOID)req->result
        );
        break;

    case CMD_PROTECT:
        ProtectVirtualMemory(
            (HANDLE)req->pid,
            req->address,
            req->size,
            req->protect
        );
        break;

    case CMD_PING:
        req->result = g_PteHook.active ? 0x50544548 : 0x4B524E4C;
        break;

    case CMD_VERIFY_PTE:
    {
        /*
         * Verification: returns PTE hook state to usermode.
         * Buffer layout (written to req->buffer):
         *   [0]   ULONG64  active          (1 if PTE hook, 0 if not)
         *   [8]   ULONG64  originalPfn     (original physical frame number)
         *   [16]  ULONG64  newPfn          (our page's physical frame number)
         *   [24]  ULONG64  targetVA        (hooked virtual address)
         *   [32]  BYTE[16] origPhysBytes   (first 16 bytes of ORIGINAL physical page at hook offset)
         *   [48]  BYTE[16] virtualBytes    (first 16 bytes of VIRTUAL page at hook address - has trampoline)
         */
        if (!req->buffer || !MmIsAddressValid((PVOID)req->buffer)) {
            req->result = 0;
            break;
        }

        PUCHAR out = (PUCHAR)req->buffer;
        RtlZeroMemory(out, 64);

        *(PULONG64)(out + 0)  = g_PteHook.active ? 1ULL : 0ULL;
        *(PULONG64)(out + 8)  = g_PteHook.originalPfn;
        *(PULONG64)(out + 16) = g_PteHook.newPfn;
        *(PULONG64)(out + 24) = (ULONG64)g_PteHook.targetVA;

        if (g_PteHook.active && g_PteHook.targetVA) {
            ULONG pageOffset = (ULONG)((ULONG64)g_PteHook.targetVA & 0xFFF);

            /* Read original physical page (what EAC sees) */
            PHYSICAL_ADDRESS origPA;
            origPA.QuadPart = (LONGLONG)(g_PteHook.originalPfn << 12);
            PVOID mapped = MmMapIoSpace(origPA, PAGE_SIZE, MmCached);
            if (mapped) {
                RtlCopyMemory(out + 32, (PUCHAR)mapped + pageOffset, 16);
                MmUnmapIoSpace(mapped, PAGE_SIZE);
            }

            /* Read current virtual page (what CPU executes - has trampoline) */
            if (MmIsAddressValid(g_PteHook.targetVA)) {
                RtlCopyMemory(out + 48, g_PteHook.targetVA, 16);
            }
        }

        req->result = 1;
        break;
    }

    case CMD_VERIFY_SPOOF:
    {
        /*
         * Return spoof call state:
         *   result = 1 if spoof active, 0 if not
         *   buffer layout:
         *     [0]  ULONG64 gadgetAddr  (ntoskrnl gadget address)
         *     [8]  ULONG64 stubAddr    (executable stub address)
         */
        if (req->buffer && MmIsAddressValid((PVOID)req->buffer)) {
            PUCHAR out = (PUCHAR)req->buffer;
            RtlZeroMemory(out, 16);
            *(PULONG64)(out + 0) = (ULONG64)g_SpoofGadget;
            *(PULONG64)(out + 8) = (ULONG64)g_SpoofStub;
        }
        req->result = (g_SpoofGadget && g_SpoofStub) ? 1 : 0;
        break;
    }

    default:
        break;
    }

    return STATUS_SUCCESS;
}
