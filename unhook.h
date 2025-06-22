............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#ifndef UNHOOK_H
#define UNHOOK_H

#include "structs.h"

#ifdef __cplusplus
extern "C" {
#endif

LPVOID MapNtdll(void);
void RehookExports(PVOID cleanBase);
BOOL Unhook(LPVOID moduleBase);

#ifdef __cplusplus
}
#endif

#endif