#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include "drv.h"
#include "asm.h"
#include "arc.h"
#include "utils.h"



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

EFI_HANDLE	gImageHandle;
EFI_SYSTEM_TABLE	*gSystemTable;
EFI_BOOT_SERVICES	*gBootServices;
EFI_RUNTIME_SERVICES	*gRuntimeServices;
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

EFI_EXIT_BOOT_SERVICES g_pOrgExitBootService = NULL;
void *Base = NULL;
EFI_IMAGE_NT_HEADERS *pHeaders = NULL;
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
	Print(L"Hi there");
	UtilWaitForKey();

	UINT8 *p = UtilFindPattern2(Base, pHeaders->OptionalHeader.SizeOfImage, "\x48\x8B\x3D\x00\x00\x00\x00\x48\x8B\xCF", "xxx????xxx");
	if (p)
	{
		Print(L"FOUND %lx\r\n", p + 3);
		//GlobalNames = reinterpret_cast<decltype(GlobalNames)>(*(UINT32*)(p + 3));
		UINT64 ldrblk = (*(UINT32*)(p + 3));
		Print(L"Here %lx\r\n", ldrblk);
		UtilWaitForKey();

		PLOADER_PARAMETER_BLOCK blk;
		blk = (PLOADER_PARAMETER_BLOCK)&ldrblk;

		Print(L"Here1 %lx\r\n", blk);
		UtilWaitForKey();

		Print(L"mehh %lx\r\n", blk->Size);
		Print(L"mehh %l\r\n", blk->OsMajorVersion);

		//Print(L"yyyy %lx\r\n", blk->BootDriverListHead.ForwardLink);

		Print(L"zzz %lc\r\n", blk->Extension->AcpiBiosVersion);
		Print(L"aaaaaaaaa %lx\r\n", blk->Extension->DrvDBSize);
		Print(L"bbbbb %lx\r\n", blk->FirmwareInformation.v.EfiRuntimePageProtectionSupported);
		Print(L"ccc %lx\r\n", blk->FirmwareInformation.v.EfiRuntimePageProtectionEnabled);

		/*while(pENTRY != NULL)
		{
		PBOOT_DRIVER_LIST_ENTRY pStrct;
		//
		// Do some processing.
		//
		pStrct = (PBOOT_DRIVER_LIST_ENTRY)CONTAINING_RECORD(pENTRY, BOOT_DRIVER_LIST_ENTRY, Link);
		//
		//Move to next Entry in list.
		//
		pENTRY = pENTRY->ForwardLink;
		Print(L"xxx %lx\r\n", pENTRY);
		}*/
		/*oOslArchTransferToKernel = (tOslArchTransferToKernel)UtilCallAddress(p);
		Print(L"OslArchTransferToKernel at %lx\r\n", oOslArchTransferToKernel);
		Print(L"OslArchTransferToKernelHook at %lx\r\n", &hkOslArchTransferToKernel);

		// Backup original function bytes before patching
		OslArchTransferToKernelCallPatchLocation = (VOID*)p;
		CopyMem((VOID*)OslArchTransferToKernelCallBackup, (VOID*)p, 5);

		// display original code
		//Print(L"Original:\r\n");
		//UtilDisassembleCode((UINT8*)p, (VOID*)p, 5);

		// Do patching
		*(UINT8*)p = 0xE8;
		*(UINT32*)(p + 1) = UtilCalcRelativeCallOffset((VOID*)p, (VOID*)&hkOslArchTransferToKernel);

		// Display patched code
		//Print(L"Patched:\r\n");
		//UtilDisassembleCode((UINT8*)p, (VOID*)p, 5);*/
	}
	else
	{
		Print(L"Not found");
	}
	UtilWaitForKey();

}

VOID *ret_ExitBootServices = NULL;


VOID EFIAPI hkOslArchTransferToKernel(PLOADER_PARAMETER_BLOCK KernelParams, VOID *KiSystemStartup)
{

	//__debugbreak();

	//
	// Before we do anything, restore original call bytes
	//
	*(UINT32*)(OslArchTransferToKernelCallPatchLocation + 1) = *(UINT32*)(OslArchTransferToKernelCallBackup + 1);

	Print(L"im in the arch transfer");
	UtilWaitForKey();
	oOslArchTransferToKernel(KernelParams, KiSystemStartup);
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
		*/
		//UINT8 *p = UtilFindPattern2(Base, pHeaders->OptionalHeader.SizeOfImage, "\x33\xF6\x4C\x8B\xE1\x4C\x8B\xEA", "xxxxxxxx");
		
		// 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0xEB, 0xFE
		// UINT8 *p = UtilFindPattern2(Base, pHeaders->OptionalHeader.SizeOfImage, "\xE8\xAA\xAA\xAA\xAA\x45\x33", "x????xx");

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
	g_pOrgExitBootService = gBS->ExitBootServices;

	gBS->ExitBootServices = _ExitBootServices;

	//if (enableHooks) eBs->ExitBootServices = ItSecExitBootServices;

    return efiStatus;
}

