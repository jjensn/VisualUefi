#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include "drv.h"
#include "asm.h"
#include "arc.h"
#include "utils.h"
#include "bootloader.h"
#include <Library/BaseLib.h>
#include <Base.h>

EFI_HANDLE	gImageHandle;
EFI_SYSTEM_TABLE	*gSystemTable;
EFI_BOOT_SERVICES	*gBootServices;
EFI_RUNTIME_SERVICES	*gRuntimeServices;

VOID* KernelBase = NULL;
UINT32 KernelSize = 0;

typedef VOID(EFIAPI *tOslFwpKernelSetupPhase1)(PLOADER_PARAMETER_BLOCK a1);

tOslFwpKernelSetupPhase1 oOslFwpKernelSetupPhase1 = NULL;

LOADER_PARAMETER_BLOCK b;

typedef __int64(*tRtlImageNtHeaderEx)(int a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 *a4);
//E8 ? ? ? ? 48 8B 45 17
UINT8 sigRtl[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0x45, 0x17 };
UINT8* ImgArchEfiStartBootApplicationPatchLocation = NULL;
UINT8 ImgArchEfiStartBootApplicationBackup[5] = { 0 };

tRtlImageNtHeaderEx oRtlImageNtHeaderEx = NULL;

typedef VOID(EFIAPI* tOslArchTransferToKernel)(PLOADER_PARAMETER_BLOCK KernelParams, VOID *KiSystemStartup);
																		   //  "\xE8\xAA\xAA\xAA\xAA\x45\x33"
																		   // E8 ? ? ? ? 45 33 C9 48 63 D3
UINT8 sigOslArchTransferToKernelCall[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0x33, 0xC9, 0x48, 0x63, 0xD3 }; // 48 8B 45 A8 33 FF
//UINT8 sigOslArchTransferToKernelCall[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCF, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCF, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0xD8, 0x85, 0xC0, 0x0F, 0x88, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8};
UINT8* OslArchTransferToKernelCallPatchLocation;
UINT8 OslArchTransferToKernelCallBackup[5];

tOslArchTransferToKernel oOslArchTransferToKernel = NULL;


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

EFI_GUID SMBIOS_TABLE_GUID =
{ 0x7ce88fb3,
0x4bd7,
0x4679,
{ 0x87, 0xa8, 0xa8, 0xd8, 0xde, 0xe5,0xd, 0x2b }
};


EFI_GUID LAUNCH_APP =
{
	0xeaea9aec,
	0xc9c1,
	0x46e2,
{ 0x9d, 0x52, 0x43, 0x2a, 0xd2, 0x5a, 0x9b, 0x0b }
};

EFI_GUID LOADED_IMAGE_PROTOCOL_GUID =
{
	0x5B1B31A1,
	0x9562,
	0x11d2,
{ 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B }
};

EFI_GUID FIRMWARE_VOLUME_PROTOCOL_GUID =
{
	0x389F751F, 0x1838, 0x4388,{ 0x83, 0x90, 0xCD, 0x81, 0x54, 0xBD, 0x27, 0xF8 }
};

EFI_GUID DEVICE_PATH_PROTOCOL_GUID =
{
	0x9576e91, 0x6d3f, 0x11d2,{ 0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b }
};

EFI_GUID EXIT_BOOT_SERVICES_GUID =
{ 0x27abf055, 0xb1b8, 0x4c26, { 0x80, 0x48, 0x74, 0x8f, 0x37, 0xba, 0xa2, 0xdf } };

EFI_GUID CC = { 0x13fa7698, 0xc831, 0x49c7,{ 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 } };

EFI_EXIT_BOOT_SERVICES g_pOrgExitBootService = NULL;
EFI_IMAGE_LOAD g_pImageLoad = NULL;
EFI_IMAGE_START g_pImageStart = NULL;

void *Base = NULL;
EFI_IMAGE_NT_HEADERS *pHeaders = NULL;
PLOADER_PARAMETER_BLOCK blk;

extern void DoTHePrint()
{
	Print(L"dickface");
}

PKLDR_DATA_TABLE_ENTRY GetLoadedModule(LIST_ENTRY* LoadOrderListHead, CHAR16* ModuleName)
{
	if (ModuleName == NULL || LoadOrderListHead == NULL)
		return NULL;

	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		PKLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Entry && (StrnCmp(Entry->BaseImageName.Buffer, ModuleName, Entry->BaseImageName.Length) == 0))
			return Entry;
	}

	return NULL;
}


EFI_STATUS
EFIAPI
UefiUnload (
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
	
	for(UINT32 i = 0; i < Size-maskLength ; i += 1)
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
	gST = gSystemTable;
	gRT = gRuntimeServices;
}


VOID
EFIAPI
CallbackSMI(
	IN  EFI_EVENT	Event,
	IN  VOID      *Context
)
{
	//CHAR8 *dest = NULL;
	//UnicodeStrToAsciiStr(b.Extension->SmbiosVersion.Buffer, dest);
	
	//AsciiPrint("%s\r\n", dest);

	Print(L"%lx\r\n", KernelSize);

	UtilWaitForKey();

}

VOID *ret_ExitBootServices = NULL;
VOID *ret_LoadImage = NULL;



VOID EFIAPI hkOslArchTransferToKernel(PLOADER_PARAMETER_BLOCK KernelParams, VOID *KiSystemStartup)
{
	//
	// Before we do anything, restore original call bytes
	//

	
	*(UINT32*)(OslArchTransferToKernelCallPatchLocation + 1) = *(UINT32*)(OslArchTransferToKernelCallBackup + 1);

	//CopyMem(&b, KernelParams, sizeof(LOADER_PARAMETER_BLOCK));

	PKLDR_DATA_TABLE_ENTRY KernelEntry = NULL;

	KernelEntry = GetLoadedModule(&KernelParams->LoadOrderListHead, L"ntoskrnl.exe");
	if (KernelEntry)
	{
		Print(L"ABC\r\n");
		KernelBase = KernelEntry->ImageBase;
		KernelSize = KernelEntry->SizeOfImage;
	}
	
	//Print(L"z");

	//KernelParams->RegistryBase = (VOID*)0x10000;

	oOslArchTransferToKernel(KernelParams, KiSystemStartup);
}

VOID EFIAPI hkOslFwpKernelSetupPhase1(PLOADER_PARAMETER_BLOCK a1)
{
	*(UINT32*)(OslArchTransferToKernelCallPatchLocation + 1) = *(UINT32*)(OslArchTransferToKernelCallBackup + 1);
	
	

	oOslFwpKernelSetupPhase1(a1);
	//DoTHePrint();
}

CHAR16 *
EFIAPI
FileDevicePathToText(EFI_DEVICE_PATH_PROTOCOL *FilePathProto)
{
	EFI_STATUS					Status;
	FILEPATH_DEVICE_PATH 				*FilePath;
	CHAR16								FilePathText[256]; // possible problem: if filepath is bigger
	CHAR16								*OutFilePathText;
	UINTN								Size;
	UINTN								SizeAll;
	UINTN								i;

	FilePathText[0] = L'\0';
	i = 4;
	SizeAll = 0;
	//DBG("FilePathProto->Type: %d, SubType: %d, Length: %d\n", FilePathProto->Type, FilePathProto->SubType, DevicePathNodeLength(FilePathProto));
	while (FilePathProto != NULL && FilePathProto->Type != END_DEVICE_PATH_TYPE && i > 0) {
		if (FilePathProto->Type == MEDIA_DEVICE_PATH && FilePathProto->SubType == MEDIA_FILEPATH_DP) {
			FilePath = (FILEPATH_DEVICE_PATH *)FilePathProto;
			Size = (DevicePathNodeLength(FilePathProto) - 4) / 2;
			if (SizeAll + Size < 256) {
				if (SizeAll > 0 && FilePathText[SizeAll / 2 - 2] != L'\\') {
					StrCat(FilePathText, L"\\");
				}
				StrCat(FilePathText, FilePath->PathName);
				SizeAll = StrSize(FilePathText);
			}
		}
		FilePathProto = NextDevicePathNode(FilePathProto);
		//DBG("FilePathProto->Type: %d, SubType: %d, Length: %d\n", FilePathProto->Type, FilePathProto->SubType, DevicePathNodeLength(FilePathProto));
		i--;
		//DBG("FilePathText: %s\n", FilePathText);
	}

	OutFilePathText = NULL;
	Size = StrSize(FilePathText);
	if (Size > 2) {
		// we are allocating mem here - should be released by caller
		Status = gBS->AllocatePool(EfiBootServicesData, Size, (VOID*)&OutFilePathText);
		if (Status == EFI_SUCCESS) {
			StrCpy(OutFilePathText, FilePathText);
		}
		else {
			OutFilePathText = NULL;
		}
	}

	return OutFilePathText;
}
//typedef EFI_STATUS(EFIAPI *tImgArchEfiStartBootApplication)(PBL_APPLICATION_ENTRY AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, PBL_RETURN_ARGUMENTS ReturnArguments);


/*EFI_STATUS EFIAPI hkImgArchEfiStartBootApplication(PBL_APPLICATION_ENTRY AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, PBL_RETURN_ARGUMENTS ReturnArguments)
{
	//PIMAGE_NT_HEADERS NtHdr = NULL;

	// Restore original bytes to call
	CopyMem(ImgArchEfiStartBootApplicationPatchLocation, ImgArchEfiStartBootApplicationBackup, 5);

	// Clear the screen
	//gST->ConOut->ClearScreen(gST->ConOut);

	//NtHdr = ImageNtHeader(ImageBase);
	//if (NtHdr != NULL)
	{
		EFI_STATUS EfiStatus = EFI_SUCCESS;
		UINT8* Found = NULL;

		// Find right location to patch
		EfiStatus = UtilFindPattern(sigOslArchTransferToKernelCall, 0xCC, sizeof(sigOslArchTransferToKernelCall), ImageBase, ImageSize, (VOID**)&Found);
		if (EfiStatus == EFI_SUCCESS)
		{
			Print(L"Found OslArchTransferToKernel call at %lx\r\n", Found);

			// Get original from call instruction
			oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress(Found);
			Print(L"OslArchTransferToKernel at %lx\r\n", oOslArchTransferToKernel);
			Print(L"OslArchTransferToKernelHook at %lx\r\n", &hkOslArchTransferToKernel);

			// Backup original function bytes before patching
			OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
			CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)Found, 5);

			// display original code
			//Print(L"Original:\r\n");
			//UtilDisassembleCode((UINT8*)Found, (VOID*)Found, 5);

			// Do patching 
			*(UINT8*)Found = 0xE8;
			*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkOslArchTransferToKernel);

			// Display patched code 
			//Print(L"Patched:\r\n");
			//UtilDisassembleCode((UINT8*)Found, (VOID*)Found, 5);
		}
		else
		{
			Print(L"\r\nImgArchEfiStartBootApplication error, failed to find OslArchTransferToKernel patch location. Status: %lx\r\n", EfiStatus);
		}
	}

	//UtilPrintLoadedImageInfo(gLocalImageInfo);

	Print(L"Press any key to continue...");
	UtilWaitForKey();

	// Clear screen
	//gST->ConOut->ClearScreen(gST->ConOut);

	return oImgArchEfiStartBootApplication(AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments);
}*/

__int64 hkRtlImageNtHeaderEx(int a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 *a4)
{
	Print(L"base %lx\r\n", a2);
	Print(L"size %lx\r\n", a3);

	UINT8* Found = NULL;;
	CopyMem(ImgArchEfiStartBootApplicationPatchLocation, ImgArchEfiStartBootApplicationBackup, 5);

	/*for (int i = 0; i < 5; i++)
	{
		UINT8 *Code = (UINT8*)(ImgArchEfiStartBootApplicationPatchLocation + i);

		Print(L"printing restored: %lx\r\n", *(Code));
	}*/

	EFI_STATUS EfiStatus = UtilFindPattern(sigOslArchTransferToKernelCall, 0xCC, sizeof(sigOslArchTransferToKernelCall), (VOID*)a2, (UINT32)a3, (VOID**)&Found);
	if (EfiStatus == EFI_SUCCESS)
	{
		Print(L"Found OslArchTransferToKernel call at %lx\r\n", Found);

		// Get original from call instruction
		//UINT8 sigTrans[] = { 0x33, 0xF6, 0x4C, 0x8B, 0xE1 };
		//UINT8* transFound = NULL;
		//UtilFindPattern(sigTrans, 0xCC, sizeof(sigTrans), (VOID*)a2, (UINT32)a3, (VOID**)&transFound);
		oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress(Found);
		//oOslFwpKernelSetupPhase1 = (tOslFwpKernelSetupPhase1)UtilCallAddress(Found);
		Print(L"final addr: %lx\r\n", oOslArchTransferToKernel);
		UtilWaitForKey();

		OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		//OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)Found, 5);


		// Do patching 
		*(UINT8*)Found = 0xE8;
		//*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkOslFwpKernelSetupPhase1);
		*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkOslArchTransferToKernel);
	}
	else
	{
		Print(L"\r\nImgArchEfiStartBootApplication error, failed to find OslArchTransferToKernel patch location. Status: %lx\r\n", EfiStatus);
	}

	//Print(L"call address aga9n %lx\r\n", oRtlImageNtHeaderEx);

	return oRtlImageNtHeaderEx(a1, a2, a3, a4);
}

EFI_STATUS
hkImageStart(
	IN  EFI_HANDLE                  ImageHandle,
	OUT UINTN                       *ExitDataSize,
	OUT CHAR16                      **ExitData    OPTIONAL
)
{

	gBS->StartImage = g_pImageStart;

	Print(L"In image start\r\n");


	EFI_STATUS				Status;
	EFI_LOADED_IMAGE_PROTOCOL		*Image;
	CHAR16					*FilePathText = NULL;
	//	CHAR16					*BootLoaders[] = BOOT_LOADERS;
//	UINTN					Index;

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
	// Extract file path from image device file path
	//
	FilePathText = FileDevicePathToText(Image->FilePath);
	if (FilePathText == NULL) {
		Print(L"ERROR: OStartImage: image file path is NULL\n");
		return EFI_INVALID_PARAMETER;
	}
	Print(L" File: %s\n", FilePathText);
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
		//Found
		for (int i = 0; i < 5; i++)
		{
			UINT8 *Code = (UINT8*)(Found + i);

			Print(L"printing old: %lx\r\n", *(Code));
		}

		*(UINT8*)Found = 0xE8; // Write call opcode
		*(UINT32*)(Found + 1) = NewCallRelative; // Write the new relative call offset

		for (int i = 0; i < 5; i++)
		{
			UINT8 *Code = (UINT8*)(Found + i);

			Print(L"printing new: %lx\r\n", *(Code));
		}

		
		Print(L"Done pathcingx\n");
	}
	else
	{
		Print(L"\r\nPatchWindowsBootManager error, failed to find Archpx64TransferTo64BitApplicationAsm patch location. Status: %lx\r\n", EfiStatus);
	}

	//UtilWaitForKey();
	//
	// Start image by calling original StartImage
	//
	FreePool(FilePathText);
	Status = g_pImageStart(ImageHandle, ExitDataSize, ExitData);

	
	
	return Status;
}



EFI_STATUS EFIAPI hkExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
	UINTN i = 0;

	// return address points to winload
	VOID *Addr = (VOID *)((UINTN)ret_ExitBootServices & 0xfffffffffffff000);

	char bFoundBase = 0;

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
		Print(L"\n\r%X\n\r", Base);
		bFoundBase = 1;
	}
	
	if (bFoundBase)
	{
		//UINT8* Found = NULL;
		
		//void *origBase = Base;
		pHeaders = (EFI_IMAGE_NT_HEADERS *)RVATOVA(Base, ((EFI_IMAGE_DOS_HEADER *)Base)->e_lfanew);

		//EFI_STATUS EfiStatus = EFI_SUCCESS;

		// Find right location to patch
		Print(L"Starting scan %lx\n", pHeaders->OptionalHeader.SizeOfImage);

		//EfiStatus = UtilFindPattern(sigOslArchTransferToKernelCall, 0xCC, sizeof(sigOslArchTransferToKernelCall), RVATOVA(Base, 0), pHeaders->OptionalHeader.SizeOfImage, (VOID**)&Found);
		/*
			33 F6 4C 8B E1 4C 8B EA
			33 F6                                           xor     esi, esi
			4C 8B E1                                        mov     r12, rcx
			4C 8B EA                                        mov     r13, rdx
			0F 09                                           wbinvd
			48 2B C0                                        sub     rax, rax
			66 8E D0

			48 8B 15 0D ED 18 00                            mov     rdx, cs:OslEntryPoint
			48 8B CF                                        mov     rcx, rdi
			E8 4D 04 12 00
		
		//UINT8 *p = UtilFindPattern2(Base, pHeaders->OptionalHeader.SizeOfImage, "\x33\xF6\x4C\x8B\xE1\x4C\x8B\xEA", "xxxxxxxx");
		
		// 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0xEB, 0xFE
		UINT8 *p = UtilFindPattern2(Base, pHeaders->OptionalHeader.SizeOfImage, "\xE8\xAA\xAA\xAA\xAA\x45\x33", "x????xx");
		
		UINT8 sigOslArchTransferToKernelCall123[] = { 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x45, 0x33 }; // 48 8B 45 A8 33 FF
		UINT8* Found = NULL;

		EFI_STATUS stat = UtilFindPattern(sigOslArchTransferToKernelCall123, 0xCC, sizeof(sigOslArchTransferToKernelCall123), Base, pHeaders->OptionalHeader.SizeOfImage, (VOID**)&Found);
		if (stat == EFI_SUCCESS)
		{
			Print(L"Found OslArchTransferToKernel call at %lx\r\n", Found);
		}

		if (p)
		{
			Print(L"Found OslArchTransferToKernel call at %lx\r\n", p);
		}
		*/
		/*oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress(Found);
		Print(L"OslArchTransferToKernel at %lx\r\n", oOslArchTransferToKernel);
		Print(L"OslArchTransferToKernelHook at %lx\r\n", &hkOslArchTransferToKernel);

		OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)Found, 5);

		// Do patching 
		*(UINT8*)Found = 0xE8;
		*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkOslArchTransferToKernel);
		*/
		UINT8 sigBlock[] = { 0x48, 0x8B, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCF }; // 48 8B 45 A8 33 FF
		UINT8* Found2 = NULL;
		
		EFI_STATUS stat2 = UtilFindPattern(sigBlock, 0xCC, sizeof(sigBlock), Base, pHeaders->OptionalHeader.SizeOfImage, (VOID**)&Found2);
		if (stat2 == EFI_SUCCESS)
		{
			UINT64 ldrblk = (*(UINT32*)(Found2 + 3));
			Print(L"Here %lx\r\n", ldrblk);
			//UtilWaitForKey();


			
			//Print(L"Found blk call at %lx\r\n", *(UINT32*)(Found2 + 3));
			PLOADER_PARAMETER_BLOCK blk2 = NULL;
			blk2 = (PLOADER_PARAMETER_BLOCK)&ldrblk;
			Print(L"%s\r\n", blk2->NtBootPathName);

			Print(L"%s\r\n", blk2->Extension->EfiVersion.Buffer);
			Print(L"%lx\r\n", blk2->OsMajorVersion);
			Print(L"%lx\r\n", blk2->RegistryLength);

			/*PKLDR_DATA_TABLE_ENTRY KernelEntry = GetLoadedModule(&blk2->LoadOrderListHead, L"ntoskrnl.exe");
			if (KernelEntry)
			{
				Print(L"got it %lx", KernelEntry->DllBase);
				//KernelBase = KernelEntry->ImageBase;
				Print(L"Size %lx\r\n", KernelEntry->SizeOfImage);
				//KernelSize = KernelEntry->SizeOfImage;
			}*/
			
			
		}
		
		//\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\xCF xxx????xxx
		
	}



	/*
	UINTN MemoryMapSize;
    EFI_MEMORY_DESCRIPTOR *MemoryMap;
    UINTN LocalMapKey;
    UINTN DescriptorSize;
    UINT32 DescriptorVersion;
    MemoryMap = NULL;
    MemoryMapSize = 0;
   
    do {  
        Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &LocalMapKey, &DescriptorSize,&DescriptorVersion);
        if (Status == EFI_BUFFER_TOO_SMALL){
            MemoryMap = AllocatePool(MemoryMapSize + 1);
            Status = gBS->GetMemoryMap(&MemoryMapSize, MemoryMap, &LocalMapKey, &DescriptorSize,&DescriptorVersion);      
        } else {
            
	}
		DbgPrint(L"This time through the memory map loop, status = %r\n", Status);

	} while (Status != EFI_SUCCESS);

	return gOrigExitBootServices(ImageHandle, LocalMapKey);
	*/

	gBS->ExitBootServices = g_pOrgExitBootService;
	
	return g_pOrgExitBootService(ImageHandle, MapKey);
}

/*VOID
EFIAPI
Callback2(
	IN  EFI_EVENT	Event,
	IN  VOID      *Context
)
{
	Print(L"in callbak2\n\r");

	UINT8 *p = UtilFindPattern2(Base, pHeaders->OptionalHeader.SizeOfImage, "\xE8\xAA\xAA\xAA\xAA\x45\x33", "x????xx");
	oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress(p);
	Print(L"OslArchTransferToKernel at %lx\r\n", oOslArchTransferToKernel);
	Print(L"OslArchTransferToKernelHook at %lx\r\n", &hkOslArchTransferToKernel);

	// Backup original function bytes before patching
	OslArchTransferToKernelCallPatchLocation = (VOID*)p;
	CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)p, 5);

	*(UINT8*)p = 0xE8;
	*(UINT32*)(p + 1) = UtilCalcRelativeCallOffset((VOID*)p, (VOID*)&hkOslArchTransferToKernel);
}*/


EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS efiStatus;

    //
    // Install required driver binding components
    //'InitializeLib(ImageHandle, SystemTable);
	InitializeLib(ImageHandle, SystemTable);
    efiStatus = EfiLibInstallDriverBindingComponentName2(ImageHandle,
                                                         SystemTable,
                                                         &gDriverBindingProtocol,
                                                         ImageHandle,
                                                         &gComponentNameProtocol,
                                                         &gComponentName2Protocol);

	EFI_EVENT Event;
	gBootServices->CreateEventEx(0x200, 0x10, &CallbackSMI, NULL, &EXIT_BOOT_SERVICES_GUID, &Event);
	//gBootServices->CreateEventEx(0x200, 0x10, &Callback2, NULL, &SMBIOS_TABLE_GUID, &Event);
	//gBootServices->CreateEventEx(0x200, 0x10, &Callback2, NULL, &CC, &Event);
	//g_pOrgExitBootService = gBS->ExitBootServices;

	//g_pImageLoad = gBS->LoadImage;

	g_pImageStart = gBS->StartImage;

	gBS->StartImage = hkImageStart;
	gBS->Hdr.CRC32 = 0;
	gBS->CalculateCrc32(gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);
	//gBS->

	//gBS->ExitBootServices = _ExitBootServices;

	//gBS->LoadImage = _LoadImage;

	//if (enableHooks) eBs->ExitBootServices = ItSecExitBootServices;

    return efiStatus;
}

