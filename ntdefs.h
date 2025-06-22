............................................................................
. Project: StealthAPI                                                      .
. Build for educational purpose in authorized lab environments only.        .
. Author: Ebere Michhael (Call Simba)                                      .
. Telegram: @lets_sudosu                                                   .
. Make the world a better place.                                           .
............................................................................

#ifndef NTDEFS_H
#define NTDEFS_H

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define NtCurrentProcess() ((HANDLE)-1)

#endif