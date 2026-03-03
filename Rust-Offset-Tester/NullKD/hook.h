#pragma once
/*
 * hook.h - dxgkrnl.sys hook for stealthy communication
 *
 * Hooks NtQueryCompositionSurfaceStatistics in dxgkrnl.sys.
 * Usermode calls this function with our REQUEST_DATA struct;
 * the hook intercepts, dispatches, and returns.
 */

#include "definitions.h"
#include "memory.h"
#include "shared.h"

namespace Hook {
    /* Install the hook on dxgkrnl.sys */
    BOOL Install(void* handlerAddr);

    /* The hook handler - dispatches commands from usermode */
    NTSTATUS Handler(PVOID callParam);
}
