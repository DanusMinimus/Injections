#pragma once
/*##############################Includes##########################################*/
#include <stdio.h>
#include <Windows.h>

/*##############################Macros#########################################*/

/*##############################Constants#########################################*/

#define NOTEPAD_PATH "C:\\WINDOWS\\SysWOW64\\notepad.exe"

/*##############################Typedef#########################################*/

/*##############################Structure Defentions##############################*/

typedef struct INJECT_ENTRY
{
	DWORD dwResourceSize;
	LPCSTR lpcstrResourceName;
	HGLOBAL lpPointerToResourceHandle;
	LPVOID lpPointerToResourceInMem;

	LPVOID pPayloadMemRet;
	DWORD dwSizeOfPayloadInInjectedMem;

	LPVOID pAddressOfEntryPointInjected;

}*PINJECT_ENTRY;

/*##############################Function Defeneitions##############################*/


/*
This function frees struct data
IN ppResourceEntry - A pointer to a PRESOURCE_ENTRY struct
*/

VOID RLOADER_freeStruct(PINJECT_ENTRY* ppInjectEntry);

/*
This function locates a resource file, maps it into memory and injects it into a process

OUT BOOL - Success code
*/
BOOL RLOADER_findMapInject();

/*
Callback(ENUMRESNAMEPROCW) function for EnumResourceNames, this function returns a resource handle to a specific resource we are looking for
IN hModule - The loaded module handle in which is currently being looked at
IN lpszType - Located resource type
IN lpszName - Located resouce name/ can also be the ID of the resource
IN lParam - A parameter to pass the Callback function, in this case - we'll pass a pointer to a resource handle that we'll fill with the handle return by FindReousrceW

OUT BOOL - Sucess Code
*/
BOOL CALLBACK RLOADER_loadResourceAndCheckPECallback(IN HMODULE hModule, IN LPCWSTR lpszType, IN LPWSTR lpszName, IN LONG_PTR lParam);

/*
This function accepts a PRESOURCE_ENTRY pointer struct and fills it with the resource data
IN lpResourceAddr - A pointer to the resource memory
IN hModuleHandle - A handle to the module in which the resource is located in
IN ppResourceEntry - A pointer to a PRESOURCE_ENTRY struct

OUT BOOL - Success Code
*/
BOOL RLOADER_LoadResourceMem(HMODULE hModuleHandle, HRSRC hResourceHandle, PINJECT_ENTRY* ppInjectEntry);

/*
This function accepts the address of the resource memory and maps it to memory, 
then it resolves the import table and rebuilds the PE using the relocation table
IN lpResourceAddr - A pointer to the resource memory
IN pResourceEntry - A PRESOURCE_ENTRY struct entry

OUT LPVOID - Address of the newly mapped resource file
*/
LPVOID RLOADER_MapResourceToFile(LPVOID lpResourceAddr, PINJECT_ENTRY * ppInjectEntry);

/*
This function acccepts the address of the PE file in memory and rebuilds its import table
IN pInjectedAddr - PE Address in memory

OUT BOOL - Success code
*/
BOOL RLOADER_rebuildImportTable(LPVOID pInjectedAddr);

/*
This function acccepts the address of the PE file in memory to match the newly allocated memory in the new process
IN pPayLoadMapped - PE Address in memory
IN pInjectedAddr - allocated memory region in new process

OUT BOOL - Success code
*/
BOOL RLOADER_rebaseReloc(LPVOID * pPayLoadMapped, LPVOID pInjectedAddr);