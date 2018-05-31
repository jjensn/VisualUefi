
#ifndef _TYPES_H_
#define _TYPES_H_

#include "arc.h"

/*
    NT-like types definitions.
*/

// 1 byte signed
typedef char                    CHAR;
typedef char *                  PCHAR;

// 1 byte unsigned
typedef unsigned char           UCHAR;
typedef unsigned char *         PUCHAR;

// 2 byte signed
typedef short                   SHORT;
typedef short *                 PSHORT;

// 2 byte unsigned
typedef unsigned short          USHORT;
typedef unsigned short *        PUSHORT;

// 4 byte signed
typedef long                    LONG;
typedef long *                  PLONG;

// 4 byte unsigned
typedef unsigned long           ULONG;
typedef unsigned long *         PULONG;

// 8 byte signed
typedef long long               LONGLONG;
typedef long long *             PLONGLONG;

// 8 byte unsigned
typedef unsigned long long      ULONGLONG;
typedef unsigned long long *    PULONGLONG;
typedef unsigned short WORD;
typedef unsigned short * PWORD;

typedef CONST CHAR *PCSTR;

// pointer sized
typedef void * PVOID;

// #########################################
typedef VOID(EFIAPI *tOslFwpKernelSetupPhase1)(PLOADER_PARAMETER_BLOCK);
tOslFwpKernelSetupPhase1 oOslFwpKernelSetupPhase1;
UINT8 sigOslFwpKernelSetupPhase1[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCF, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0xCC, 0xCC, 0xCC, 0xCC, 0x48};
UINT8* OslFwpKernelSetupPhase1PatchLocation;
UINT8 OslFwpKernelSetupPhase1Backup[5] = { 0 };

typedef __int64(*tRtlImageNtHeaderEx)(int a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 *a4);
UINT8 sigRtl[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x45, 0x17 };
UINT8* ImgArchEfiStartBootApplicationPatchLocation;
UINT8 ImgArchEfiStartBootApplicationBackup[5] = { 0 };
tRtlImageNtHeaderEx oRtlImageNtHeaderEx;

typedef VOID(EFIAPI* tOslArchTransferToKernel)(PLOADER_PARAMETER_BLOCK KernelParams, VOID *KiSystemStartup);
UINT8 sigOslArchTransferToKernelCall[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0x33, 0xC9, 0x48, 0x63, 0xD3 }; // 48 8B 45 A8 33 FF
UINT8* OslArchTransferToKernelCallPatchLocation;
UINT8 OslArchTransferToKernelCallBackup[5];
tOslArchTransferToKernel oOslArchTransferToKernel;

UINT8 sigInitPatchGuard[] = { 0x75, 0x2D, 0x0F, 0xB6, 0x15 };
UINTN sigInitPatchGuardSize = 5;
VOID* InitPatchGuardPatchLocation = NULL;

typedef ULONG (*tDbgPrintEx)(
	ULONG ComponentId,
	ULONG Level,
	PCSTR Format,
	...
);

#endif
