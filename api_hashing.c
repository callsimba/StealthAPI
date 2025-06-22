/*
 * Project: StealthAPI
 * Build for educational purpose.
 * Author: Ebere Michhael (Call Simba)
 * Telegram: @lets_sudosu
 * Make the world a better place.
 *
 * Brief: Provides runtime resolution of Windows APIs and modules by hashing their names,
 *        avoiding static import tables and enabling stealthy lookups.
 */

#include <Windows.h>
#include "structs.h"
#include "functions.h"
#include "strings.h"

#define INITIAL_HASH 5381
#define INITIAL_SEED 5

DWORD HashStringDjb2A(PCHAR String) {
    ULONG Hash = INITIAL_HASH;
    INT c;
    while ((c = *String++) != 0)
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;
    return Hash;
}

DWORD HashStringCRC32A(PCHAR String) {
    DWORD crc = 0xFFFFFFFF;
    while (*String) {
        crc ^= (DWORD)(*String++);
        for (int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

DWORD HashStringMurmur3A(PCHAR String) {
    const UINT32 seed = 0;
    UINT32 hash = seed;
    while (*String) {
        hash = (hash ^ (UINT32)(*String++)) * 0x5bd1e995;
        hash = (hash << 13) | (hash >> 19);
    }
    return hash;
}

DWORD HashStringRandom(PCHAR String, DWORD hashType) {
    switch (hashType % 3) {
        case 0: return HashStringDjb2A(String);
        case 1: return HashStringCRC32A(String);
        default: return HashStringMurmur3A(String);
    }
}

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash, DWORD hashType) {
    if (!hModule || !dwApiNameHash) return NULL;

    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)
        (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD names = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD funcs = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD ords   = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        CHAR* name = (CHAR*)(pBase + names[i]);
        if (dwApiNameHash == HashStringRandom(name, hashType))
            return (FARPROC)(pBase + funcs[ords[i]]);
    }
    return NULL;
}

HMODULE GetModuleHandleH(DWORD dwModuleNameHash, DWORD hashType) {
    if (!dwModuleNameHash) return NULL;

#ifdef _WIN64
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#else
    PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLDR_DATA_TABLE_ENTRY pEnt = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;

    while (pEnt) {
        if (pEnt->FullDllName.Length && pEnt->FullDllName.Length < MAX_PATH) {
            CHAR upper[MAX_PATH] = {0};
            for (DWORD i = 0; pEnt->FullDllName.Buffer[i]; i++)
                upper[i] = (CHAR)toupper(pEnt->FullDllName.Buffer[i]);

            if (HashStringRandom(upper, hashType) == dwModuleNameHash)
                return (HMODULE)pEnt->Reserved2[0];
        }
        pEnt = *(PLDR_DATA_TABLE_ENTRY*)pEnt;
    }
    return NULL;
}
