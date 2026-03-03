/*
 * driver.cpp - Driver entry point
 *
 * Loaded by kdmapper. On entry:
 *   1. Clean all traces (PiDDB, MmUnloadedDrivers)
 *   2. Install dxgkrnl.sys hook for communication
 *   3. Hide driver object completely
 *
 * After this, the driver is invisible to all standard
 * enumeration tools and BattlEye scanning.
 */

#include "driver.h"
#include "hook.h"
#include "cleaner.h"

/* ── Real Entry (called after DriverEntry) ───────────────────────── */

static NTSTATUS RealEntry(PDRIVER_OBJECT DriverObject)
{
    /* 1. Install dxgkrnl hook */
    if (!Hook::Install(&Hook::Handler)) {
        /* Hook failed — critical error, cannot communicate */
        return STATUS_UNSUCCESSFUL;
    }

    /* 2. Clean all traces and hide driver */
    CleanAllTraces(DriverObject);

    /* Driver is now:
     *   - Hidden from PsLoadedModuleList
     *   - PiDDB entry for iqvw64e.sys removed
     *   - MmUnloadedDrivers entry cleaned
     *   - PE headers erased
     *   - DriverObject fields NULLed
     *   - Communication via hooked dxgkrnl function
     */

    return STATUS_SUCCESS;
}

/* ── DriverEntry ─────────────────────────────────────────────────── */

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    return RealEntry(DriverObject);
}