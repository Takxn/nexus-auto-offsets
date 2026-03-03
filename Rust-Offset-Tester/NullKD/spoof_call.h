/*
 * spoof_call.h - Return address spoofing for EAC evasion
 *
 * When our manually-mapped driver calls kernel APIs, the return address
 * on the stack points to unmapped memory — detectable by EAC stack walks.
 *
 * Solution: route calls through a gadget in ntoskrnl.exe so the callee
 * sees a return address inside a legitimate module.
 *
 * Flow:
 *   1. Find "add rsp, 0x28; ret" gadget in ntoskrnl at init
 *   2. SpoofCall() sets up a fake stack frame:
 *      [RSP]      = gadget address (what callee sees as return addr)
 *      [RSP+0x30] = our REAL return address
 *   3. JMP (not CALL) to target function
 *   4. Target returns to gadget → gadget does add rsp,0x28; ret → back to us
 */

#pragma once
#include "definitions.h"

/* ── Gadget storage ──────────────────────────────────────────────── */

static PVOID g_SpoofGadget = NULL;  /* addr of "add rsp, 0x28; ret" in ntoskrnl */

/* ── Find gadget in ntoskrnl ─────────────────────────────────────── */

static BOOLEAN FindSpoofGadget()
{
    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);
    if (!bytes) return FALSE;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)
        ExAllocatePoolWithTag(NonPagedPool, bytes, 'fpSK');
    if (!modules) return FALSE;

    if (!NT_SUCCESS(ZwQuerySystemInformation(
            SystemModuleInformation, modules, bytes, &bytes))) {
        ExFreePoolWithTag(modules, 'fpSK');
        return FALSE;
    }

    PVOID ntBase = modules->Modules[0].ImageBase;
    ExFreePoolWithTag(modules, 'fpSK');
    if (!ntBase) return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(ntBase);
    if (!ntHeaders) return FALSE;
    ULONG ntSize = ntHeaders->OptionalHeader.SizeOfImage;

    /*
     * Pattern: 48 83 C4 28 C3
     *   add rsp, 0x28
     *   ret
     * Very common function epilogue in ntoskrnl.
     */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        /* Only scan executable sections */
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        if (section->Misc.VirtualSize < 5)
            continue;

        PUCHAR start = (PUCHAR)ntBase + section->VirtualAddress;
        ULONG  size  = section->Misc.VirtualSize;

        if (section->VirtualAddress + size > ntSize)
            size = ntSize - section->VirtualAddress;

        for (ULONG j = 0; j + 5 <= size; j++) {
            if (start[j]     == 0x48 &&
                start[j + 1] == 0x83 &&
                start[j + 2] == 0xC4 &&
                start[j + 3] == 0x28 &&
                start[j + 4] == 0xC3)
            {
                g_SpoofGadget = &start[j];
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* ── Shellcode-based spoof caller ────────────────────────────────── */
/*
 * Shellcode that shifts arguments and builds a spoofed stack frame.
 *
 * Called as: stub(targetFn, arg1, arg2, arg3, arg4)
 *   RCX = target function pointer
 *   RDX = arg1, R8 = arg2, R9 = arg3, [RSP+0x28] = arg4
 *
 * The stub:
 *   1. Pops real return address into R11
 *   2. Shifts args: RCX←RDX, RDX←R8, R8←R9, R9←[stack]
 *   3. Builds frame: [RSP] = gadget, [RSP+0x30] = real return
 *   4. JMP to target
 *
 * Encoding (44 bytes + 8 bytes gadget addr = 52 total):
 *   41 5B                 pop r11
 *   48 8B C1              mov rax, rcx
 *   48 8B CA              mov rcx, rdx
 *   49 8B D0              mov rdx, r8
 *   4D 8B C1              mov r8, r9
 *   4C 8B 4C 24 20        mov r9, [rsp+0x20]
 *   48 83 EC 38           sub rsp, 0x38
 *   49 BA [8-byte gadget] mov r10, <gadget_imm64>
 *   4C 89 14 24           mov [rsp], r10
 *   4C 89 5C 24 30        mov [rsp+0x30], r11
 *   FF E0                 jmp rax
 */

#pragma pack(push, 1)
typedef struct _SPOOF_STUB {
    UCHAR code[52];
} SPOOF_STUB;
#pragma pack(pop)

static UCHAR g_SpoofCode[52] = {
    0x41, 0x5B,                                     /* pop r11              */
    0x48, 0x8B, 0xC1,                               /* mov rax, rcx         */
    0x48, 0x8B, 0xCA,                               /* mov rcx, rdx         */
    0x49, 0x8B, 0xD0,                               /* mov rdx, r8          */
    0x4D, 0x8B, 0xC1,                               /* mov r8, r9           */
    0x4C, 0x8B, 0x4C, 0x24, 0x20,                   /* mov r9, [rsp+0x20]   */
    0x48, 0x83, 0xEC, 0x38,                         /* sub rsp, 0x38        */
    0x49, 0xBA,                                     /* mov r10, imm64 ...   */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ... gadget address   */
    0x4C, 0x89, 0x14, 0x24,                         /* mov [rsp], r10       */
    0x4C, 0x89, 0x5C, 0x24, 0x30,                   /* mov [rsp+0x30], r11  */
    0xFF, 0xE0                                      /* jmp rax              */
};

/* Executable copy allocated at init */
static PVOID g_SpoofStub = NULL;

static BOOLEAN InitSpoofStub()
{
    if (!g_SpoofGadget)
        return FALSE;

    /* Allocate executable memory for the stub */
    g_SpoofStub = ExAllocatePoolWithTag(NonPagedPoolExecute, sizeof(g_SpoofCode), 'pfSK');
    if (!g_SpoofStub)
        return FALSE;

    /* Copy shellcode and patch gadget address at offset 25 */
    RtlCopyMemory(g_SpoofStub, g_SpoofCode, sizeof(g_SpoofCode));
    *(PVOID*)((PUCHAR)g_SpoofStub + 25) = g_SpoofGadget;

    return TRUE;
}

/* ── Typed spoof call wrappers ───────────────────────────────────── */
/*
 * These cast the shellcode stub to the appropriate function pointer type.
 * The stub takes the REAL target function as its first arg, then shifts
 * the remaining args to the correct positions.
 *
 * Usage: SpoofCall1(PsLookupProcessByProcessId, pid, &process)
 *        where the "1" suffix indicates the function normally takes 2 args
 *        but we pass target + 2 args = 3 total to the stub.
 */

/* Target takes 1 arg */
typedef NTSTATUS (*fn_spoof_1)(PVOID target, PVOID a1);
#define SpoofCall1(fn, a1) \
    ((fn_spoof_1)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1))

/* Target takes 2 args */
typedef NTSTATUS (*fn_spoof_2)(PVOID target, PVOID a1, PVOID a2);
#define SpoofCall2(fn, a1, a2) \
    ((fn_spoof_2)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1), (PVOID)(ULONG_PTR)(a2))

/* Target takes 3 args */
typedef NTSTATUS (*fn_spoof_3)(PVOID target, PVOID a1, PVOID a2, PVOID a3);
#define SpoofCall3(fn, a1, a2, a3) \
    ((fn_spoof_3)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1), \
     (PVOID)(ULONG_PTR)(a2), (PVOID)(ULONG_PTR)(a3))

/* Target takes 4 args */
typedef NTSTATUS (*fn_spoof_4)(PVOID target, PVOID a1, PVOID a2, PVOID a3, PVOID a4);
#define SpoofCall4(fn, a1, a2, a3, a4) \
    ((fn_spoof_4)g_SpoofStub)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1), \
     (PVOID)(ULONG_PTR)(a2), (PVOID)(ULONG_PTR)(a3), (PVOID)(ULONG_PTR)(a4))

/* ── Init / Cleanup ──────────────────────────────────────────────── */

static BOOLEAN InitSpoofCall()
{
    if (!FindSpoofGadget())
        return FALSE;
    return InitSpoofStub();
}

static VOID CleanupSpoofCall()
{
    if (g_SpoofStub) {
        ExFreePoolWithTag(g_SpoofStub, 'pfSK');
        g_SpoofStub = NULL;
    }
}
