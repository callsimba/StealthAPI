............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#pragma once

#ifndef SW3_HEADER_H_
#define SW3_HEADER_H_

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include "structs.h"
#include "win32api.h"

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
typedef ULONG ACCESS_MASK;
#endif

#define SW3_SEED        0x51EBD349
#define SW3_ROL8(v)     ((v << 8) | (v >> 24))
#define SW3_ROR8(v)     ((v >> 8) | (v << 24))
#define SW3_ROX8(v)     ((SW3_SEED % 2) ? SW3_ROL8(v) : SW3_ROR8(v))
#define SW3_MAX_ENTRIES 600
#define SW3_RVA2VA(Type, DllBase, Rva) \
    (Type)((ULONG_PTR)(DllBase) + (Rva))
#define SW3_HASH(name) SW3_HashSyscall(#name)

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27
} PROCESSINFOCLASS;

typedef VOID (NTAPI *KNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE PKNORMAL_ROUTINE;

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PKNORMAL_ROUTINE ApcRoutine,
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);

typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (NTAPI *NtClose_t)(
    HANDLE Handle
);

typedef NTSTATUS (NTAPI *NtDuplicateObject_t)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *NtResumeThread_t)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef struct _NT_FUNCTIONS {
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory;
    NtProtectVirtualMemory_t pNtProtectVirtualMemory;
    NtFreeVirtualMemory_t pNtFreeVirtualMemory;
    NtWriteVirtualMemory_t pNtWriteVirtualMemory;
    NtQueueApcThread_t pNtQueueApcThread;
    NtCreateSection_t pNtCreateSection;
    NtMapViewOfSection_t pNtMapViewOfSection;
    NtUnmapViewOfSection_t pNtUnmapViewOfSection;
    NtClose_t pNtClose;
    NtDuplicateObject_t pNtDuplicateObject;
    NtQueryInformationProcess_t pNtQueryInformationProcess;
    NtCreateThreadEx_t pNtCreateThreadEx;
    NtResumeThread_t pNtResumeThread;
} NT_FUNCTIONS;

#define NT_SYSCALL_LIST(_) \
    _(NtAllocateVirtualMemory, SW3_HASH(NtAllocateVirtualMemory), pNtAllocateVirtualMemory, 6, \
      (HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect), \
      (ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect)) \
    _(NtProtectVirtualMemory, SW3_HASH(NtProtectVirtualMemory), pNtProtectVirtualMemory, 5, \
      (HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect), \
      (ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)) \
    _(NtFreeVirtualMemory, SW3_HASH(NtFreeVirtualMemory), pNtFreeVirtualMemory, 4, \
      (HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType), \
      (ProcessHandle, BaseAddress, RegionSize, FreeType)) \
    _(NtWriteVirtualMemory, SW3_HASH(NtWriteVirtualMemory), pNtWriteVirtualMemory, 5, \
      (HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten), \
      (ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)) \
    _(NtQueueApcThread, SW3_HASH(NtQueueApcThread), pNtQueueApcThread, 5, \
      (HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2), \
      (ThreadHandle, ApcRoutine, NormalContext, SystemArgument1, SystemArgument2)) \
    _(NtCreateSection, SW3_HASH(NtCreateSection), pNtCreateSection, 7, \
      (PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle), \
      (SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)) \
    _(NtMapViewOfSection, SW3_HASH(NtMapViewOfSection), pNtMapViewOfSection, 10, \
      (HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect), \
      (SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)) \
    _(NtUnmapViewOfSection, SW3_HASH(NtUnmapViewOfSection), pNtUnmapViewOfSection, 2, \
      (HANDLE ProcessHandle, PVOID BaseAddress), \
      (ProcessHandle, BaseAddress)) \
    _(NtClose, SW3_HASH(NtClose), pNtClose, 1, \
      (HANDLE Handle), \
      (Handle)) \
    _(NtDuplicateObject, SW3_HASH(NtDuplicateObject), pNtDuplicateObject, 7, \
      (HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options), \
      (SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options)) \
    _(NtQueryInformationProcess, SW3_HASH(NtQueryInformationProcess), pNtQueryInformationProcess, 5, \
      (HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength), \
      (ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)) \
    _(NtCreateThreadEx, SW3_HASH(NtCreateThreadEx), pNtCreateThreadEx, 11, \
      (PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList), \
      (ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList)) \
    _(NtResumeThread, SW3_HASH(NtResumeThread), pNtResumeThread, 2, \
      (HANDLE ThreadHandle, PULONG PreviousSuspendCount), \
      (ThreadHandle, PreviousSuspendCount))

typedef struct _SW3_SYSCALL_ENTRY {
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, *PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST {
    DWORD Count;
    SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, *PSW3_SYSCALL_LIST;

typedef struct _SW3_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} SW3_PEB_LDR_DATA, *PSW3_PEB_LDR_DATA;

typedef struct _SW3_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} SW3_LDR_DATA_TABLE_ENTRY, *PSW3_LDR_DATA_TABLE_ENTRY;

typedef struct _SW3_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PSW3_PEB_LDR_DATA Ldr;
} SW3_PEB, *PSW3_PEB;

#ifdef __cplusplus
extern "C" {
#endif

extern NT_FUNCTIONS g_NtFunctions;
extern SW3_SYSCALL_LIST SW3_SyscallList;
extern PVOID g_SyscallStub;
extern Win32ApiTable g_Win32ApiTable;

void MyStrCat(char* dest, size_t destSize, const char* prefix, const char* suffix);
void EncryptString(char* str, BYTE key);
void DecryptStringWithKey(char* str, BYTE key);
BOOL IsDebugged();
BOOL IsVM();
BOOL IsSandbox();
DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList(PVOID CleanNtdllBase);
BOOL InitializeWin32ApiTable(void);
BOOL SW3_GetSSN(DWORD FunctionHash, PDWORD Ssn);
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash);
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
BOOL InitializeSyscallStub(void);
BOOL InitializeNtWrappers(void);

#define DECLARE_NT_WRAPPER_PROTO(name, hash, fallback, numArgs, sig, args) \
    EXTERN_C NTSTATUS NTAPI name sig;
NT_SYSCALL_LIST(DECLARE_NT_WRAPPER_PROTO)

#ifdef __cplusplus
}
#endif

#endif