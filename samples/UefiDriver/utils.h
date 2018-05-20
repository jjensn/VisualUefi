#pragma once

// Libraries
#include <Library/UefiLib.h>

// Protocols
#include <Protocol/LoadedImage.h>

// 
// Print info about loaded image
// 
VOID UtilPrintLoadedImageInfo(IN EFI_LOADED_IMAGE *ImageInfo);

//
// Wait for key to be pressed before further execution
//
VOID UtilWaitForKey(VOID);

// 
// Try to find file by browsing each device
// 
EFI_STATUS UtilLocateFile(IN CHAR16* ImagePath, OUT EFI_DEVICE_PATH** DevicePath);

//
// Find byte pattern starting at specified address
//
EFI_STATUS UtilFindPattern(IN UINT8* Pattern, IN UINT8 Wildcard, IN UINT32 PatternLength, VOID* Base, UINT32 Size, OUT VOID** Found);

//
// Get's call address from call instruction (0xE8)
//
VOID* UtilCallAddress(IN VOID* CallAddress);

//
// Calculates a relative offset to the target from the call address
//
UINT32 UtilCalcRelativeCallOffset(IN VOID* CallAddress, IN VOID* TargetAddress);

//
// Calculates code size by searching for next 0xCC INT3 instruction
//
UINT32 UtilCodeSize(IN UINT8* CodeStart);

//
// Displays x64 disassembly at specified address
//
//VOID UtilDisassembleCode(IN UINT8* CodeStart, IN VOID* VirtualAddress, IN UINT32 Length);