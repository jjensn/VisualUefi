
VOID * EFIAPI get_addr(VOID);

/*
Stubs for hooked functions
*/

EFI_STATUS EFIAPI _ExitBootServices(
	EFI_HANDLE ImageHandle,
	UINTN Key
);

EFI_STATUS EFIAPI
_LoadImage(
	IN  BOOLEAN                      BootPolicy,
	IN  EFI_HANDLE                   ParentImageHandle,
	IN  EFI_DEVICE_PATH_PROTOCOL     *DevicePath,
	IN  VOID                         *SourceBuffer OPTIONAL,
	IN  UINTN                        SourceSize,
	OUT EFI_HANDLE                   *ImageHandle
);