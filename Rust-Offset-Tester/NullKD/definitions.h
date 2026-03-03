#pragma once
/*
 * definitions.h - Core kernel definitions and undocumented imports
 */

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include <windef.h>
#include <ntstrsafe.h>

#pragma comment(lib, "ntoskrnl.lib")

/* ── System Information Classes ──────────────────────────────────── */

typedef enum _SYSTEM_INFORMATION_CLASS_EX {
    SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS_EX;

/* ── System module structures ────────────────────────────────────── */

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    ULONG   Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    CHAR    FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/* ── PiDDB Cache Entry ───────────────────────────────────────────── */

typedef struct PiDDBCacheEntry {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    char            _pad[16];
} PIDCacheobj;

/* ── PEB / LDR structures (for module enumeration) ───────────────── */

typedef struct _PEB_LDR_DATA_KM {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  ModuleListLoadOrder;
    LIST_ENTRY  ModuleListMemoryOrder;
    LIST_ENTRY  ModuleListInitOrder;
} PEB_LDR_DATA_KM, *PPEB_LDR_DATA_KM;

typedef struct _LDR_DATA_TABLE_ENTRY_KM {
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_KM, *PLDR_DATA_TABLE_ENTRY_KM;

typedef struct _PEB_KM {
    UCHAR       Reserved1[2];
    UCHAR       BeingDebugged;
    UCHAR       Reserved2[1];
    PVOID       Reserved3[2];
    PPEB_LDR_DATA_KM Ldr;
} PEB_KM, *PPEB_KM;

/* ── Undocumented kernel exports ─────────────────────────────────── */

extern "C" {

NTKERNELAPI PPEB_KM PsGetProcessPeb(IN PEPROCESS Process);

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS   SourceProcess,
    PVOID       SourceAddress,
    PEPROCESS   TargetProcess,
    PVOID       TargetAddress,
    SIZE_T      BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T     ReturnSize
);

NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    PSIZE_T ProtectSize,
    ULONG   NewProtect,
    PULONG  OldProtect
);

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(
    PVOID   ImageBase,
    PCCH    RoutineName
);

NTSTATUS ZwQuerySystemInformation(
    ULONG   InfoClass,
    PVOID   Buffer,
    ULONG   Length,
    PULONG  ReturnLength
);

} /* extern "C" */

/* ── Globals ─────────────────────────────────────────────────────── */

extern POBJECT_TYPE* PsProcessType;
