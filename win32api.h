............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef BOOL (WINAPI *VirtualFree_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI *VirtualQuery_t)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef SIZE_T (WINAPI *VirtualQueryEx_t)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef HMODULE (WINAPI *GetModuleHandleA_t)(LPCSTR lpModuleName);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef BOOL (WINAPI *FreeLibrary_t)(HMODULE hLibModule);
typedef VOID (WINAPI *GetSystemInfo_t)(LPSYSTEM_INFO lpSystemInfo);
typedef BOOL (WINAPI *GetFileAttributesExA_t)(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
typedef HRSRC (WINAPI *FindResourceA_t)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
typedef HGLOBAL (WINAPI *LoadResource_t)(HMODULE hModule, HRSRC hResInfo);
typedef LPVOID (WINAPI *LockResource_t)(HGLOBAL hResData);
typedef DWORD (WINAPI *SizeofResource_t)(HMODULE hModule, HRSRC hResInfo);
typedef LPVOID (WINAPI *VirtualAllocEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *WriteProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef BOOL (WINAPI *VirtualFreeEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef DWORD (WINAPI *SleepEx_t)(DWORD dwMilliseconds, BOOL bAlertable);
typedef BOOL (WINAPI *OpenProcessToken_t)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL (WINAPI *GetTokenInformation_t)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE hObject);
typedef BOOL (WINAPI *CreateProcessA_t)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL (WINAPI *TerminateProcess_t)(HANDLE hProcess, UINT uExitCode);
typedef DWORD (WINAPI *WaitForSingleObject_t)(HANDLE hHandle, DWORD dwMilliseconds);
typedef DWORD (WINAPI *GetModuleFileNameA_t)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI *MoveFileExA_t)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags);
typedef HANDLE (WINAPI *CreateThread_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef HANDLE (WINAPI *CreateRemoteThread_t)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL (WINAPI *IsDebuggerPresent_t)(VOID);
typedef BOOL (WINAPI *DuplicateHandle_t)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
typedef DWORD (WINAPI *ResumeThread_t)(HANDLE hThread);
typedef DWORD (WINAPI *SuspendThread_t)(HANDLE hThread);
typedef BOOL (WINAPI *GetThreadContext_t)(HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL (WINAPI *SetThreadContext_t)(HANDLE hThread, CONST CONTEXT* lpContext);

typedef struct _Win32ApiTable {
    VirtualAlloc_t pVirtualAlloc;
    VirtualProtect_t pVirtualProtect;
    VirtualFree_t pVirtualFree;
    VirtualQuery_t pVirtualQuery;
    VirtualQueryEx_t pVirtualQueryEx;
    GetModuleHandleA_t pGetModuleHandleA;
    GetProcAddress_t pGetProcAddress;
    LoadLibraryA_t pLoadLibraryA;
    FreeLibrary_t pFreeLibrary;
    GetSystemInfo_t pGetSystemInfo;
    GetFileAttributesExA_t pGetFileAttributesExA;
    FindResourceA_t pFindResourceA;
    LoadResource_t pLoadResource;
    LockResource_t pLockResource;
    SizeofResource_t pSizeofResource;
    VirtualAllocEx_t pVirtualAllocEx;
    WriteProcessMemory_t pWriteProcessMemory;
    VirtualFreeEx_t pVirtualFreeEx;
    SleepEx_t pSleepEx;
    OpenProcessToken_t pOpenProcessToken;
    GetTokenInformation_t pGetTokenInformation;
    CloseHandle_t pCloseHandle;
    CreateProcessA_t pCreateProcessA;
    TerminateProcess_t pTerminateProcess;
    WaitForSingleObject_t pWaitForSingleObject;
    GetModuleFileNameA_t pGetModuleFileNameA;
    CreateFileA_t pCreateFileA;
    MoveFileExA_t pMoveFileExA;
    CreateThread_t pCreateThread;
    CreateRemoteThread_t pCreateRemoteThread;
    IsDebuggerPresent_t pIsDebuggerPresent;
    DuplicateHandle_t pDuplicateHandle;
    ResumeThread_t pResumeThread;
    SuspendThread_t pSuspendThread;
    GetThreadContext_t pGetThreadContext;
    SetThreadContext_t pSetThreadContext;
} Win32ApiTable, *PWin32ApiTable;

extern Win32ApiTable g_Win32ApiTable;

#ifdef __cplusplus
}
#endif