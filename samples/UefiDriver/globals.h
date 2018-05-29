#pragma once

#define TO_MILLISECONDS(_seconds_) ((_seconds_) * 1000)
#define TO_MICROSECONDS(_seconds_) (TO_MILLISECONDS(_seconds_) * 1000)
#define TO_NANOSECONDS(_seconds_) (TO_MICROSECONDS(_seconds_) * 1000)

#define FPTR32 "0x%x"
#define FPTR64 "0x%llx"
#if defined(_M_X64) || defined(__amd64__)
#define FPTR FPTR64
#else
#define FPTR FPTR32
#endif



VOID *ret_ExitBootServices = NULL;

#define RVATOVA(_base_, _offset_) ((UCHAR*)(_base_) + (UINT32)(_offset_))

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
{ 0x27abf055, 0xb1b8, 0x4c26,{ 0x80, 0x48, 0x74, 0x8f, 0x37, 0xba, 0xa2, 0xdf } };

EFI_GUID CC = { 0x13fa7698, 0xc831, 0x49c7,{ 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 } };

EFI_GUID EFI_EVENT_GROUP_MEMORY_MAP_CHANGE =
{ 0x78bee926, 0x692f, 0x48fd, { 0x9e, 0xdb, 0x1, 0x42, 0x2e, 0xf0, 0xd7, 0xab } };


EFI_GUID EFI_EVENT_GROUP_READY_TO_BOOT =
{ 0x7ce88fb3, 0x4bd7, 0x4679, { 0x87, 0xa8, 0xa8, 0xd8, 0xde, 0xe5, 0x0d, 0x2b } };