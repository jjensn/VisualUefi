#include "drv.h"
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

VOID UtilWaitForKey(VOID)
{
	UINTN index = 0;
	EFI_INPUT_KEY key = { 0 };
	gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &index);
	gST->ConIn->ReadKeyStroke(gST->ConIn, &key);
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

}
VOID *ret_ExitBootServices = NULL;
EFI_STATUS hkExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
	Print(L"In ExitBoot");
	UtilWaitForKey();

	UINTN i = 0;

	// return address points to winload
	VOID *Base = NULL, *Addr = (VOID *)((UINTN)ret_ExitBootServices & 0xfffffffffffff000);

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

	if (Base == NULL)
	{
		Print(L"failed");
	}
	else
	{
		Print(L"%X", Base);
	}

	EFI_STATUS efiStatus = g_pOrgExitBootService(ImageHandle, MapKey);

	// Now get Winload target address
	//EFI_STATUS searchStatus = PatchWinload(startAddr, maxNumBytes);

	UtilWaitForKey();
	return efiStatus;
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

	//gBootServices->CreateEventEx(0x200, 0x10, &CallbackSMI, NULL, &EXIT_BOOT_SERVICES_GUID, &Event);
	g_pOrgExitBootService = gBS->ExitBootServices;

	gBS->ExitBootServices = hkExitBootServices;

	//if (enableHooks) eBs->ExitBootServices = ItSecExitBootServices;

    return efiStatus;
}

