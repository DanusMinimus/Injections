#pragma once
/*##############################Includes##########################################*/
#include "dhook.h"

/*##############################Function Defentions##############################*/

VOID DHOOK_initGlobalHook(LPVOID lpFuncAddr, LPVOID lpReplaceAddr)
{
	pgHookData = (PDHOOK_HOOKDATA)malloc(sizeof(DHOOK_HOOKDATA));
	pgHookData->pHookedFunc = lpFuncAddr;
	pgHookData->pReplacmentFunc = lpReplaceAddr;
}

BOOL DHOOK_isSafeToHook(IN LPVOID lpFuncAddr)
{
	BOOL bReturnVal = FALSE;
	BYTE bFirstByte = (BYTE)(*((BYTE*)(lpFuncAddr)));

	switch (bFirstByte)
	{
	case(JMP):
		goto lbl_cleanup;
	case(CALL):
		goto lbl_cleanup;
	case(INTC):
		goto lbl_cleanup;
	case(RET):
		goto lbl_cleanup;
	default:
		break;
	}

	bReturnVal = TRUE;

lbl_cleanup:
	return bReturnVal;
}

BOOL DHOOK_patchAPI(IN LPVOID lpFuncAddr, IN LPVOID lpTramp, IN LPBYTE * ppbByteArray)
{
	SIZE_T dwDelta;
	LPBYTE pbByteArray;

	BOOL bReturnVal = FALSE;
	BOOL bGenericBool = FALSE;
	DWORD dwOldProtect = 0;
	HANDLE hProcessHandle = FALSE;

	BYTE pbJumpByte[PATCH_JMP_SIZE] = { 0xE9 };

	/*Check if we can hook the function*/
	bGenericBool = DHOOK_isSafeToHook(lpFuncAddr);
	IS_ZERO("DHOOK_isSafeToHook", bGenericBool, lbl_cleanup);

	*ppbByteArray = (LPBYTE)malloc(sizeof(BYTE) * 5);
	pbByteArray = *ppbByteArray;
	
	/*Calculate the relative delta*/
	dwDelta = (SIZE_T)lpTramp - (SIZE_T)lpFuncAddr - PATCH_JMP_SIZE;

	memcpy_s(pbJumpByte + 1, PATCH_JMP_SIZE, &dwDelta, sizeof(DWORD));
	
	/*Prepare hooked page for overwrite*/
	bGenericBool = VirtualProtect(lpFuncAddr, PATCH_JMP_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	IS_ZERO("VirtualProtect", bGenericBool, lbl_cleanup);

	/*Overwrite data*/
	memcpy_s(pbByteArray, PATCH_JMP_SIZE, lpFuncAddr, PATCH_JMP_SIZE);
	memcpy_s((PBYTE)lpFuncAddr, PATCH_JMP_SIZE, pbJumpByte, PATCH_JMP_SIZE);

	/*Return to previous paging protection*/
	bGenericBool = VirtualProtect(lpFuncAddr, PATCH_JMP_SIZE, dwOldProtect, &dwOldProtect);

	IS_ZERO("VirtualProtect", bGenericBool, lbl_cleanup);

	hProcessHandle = GetCurrentProcess();

	IS_ZERO("GetCurrentProcess", hProcessHandle, lbl_cleanup);

	bGenericBool = FlushInstructionCache(hProcessHandle, lpFuncAddr, PATCH_JMP_SIZE);

	IS_ZERO("FlushInstructionCache", bGenericBool, lbl_cleanup);

	bReturnVal = TRUE;

lbl_cleanup:
	return bReturnVal;
}

LPVOID DHOOK_allocTrampoline()
{
	LPVOID pReturnVal = NULL;
	SIZE_T nQueryBytes = 0;
	SYSTEM_INFO siSysInfo = { 0 };
	MEMORY_BASIC_INFORMATION mbiBasicInfo = { 0 };

	GetSystemInfo(&siSysInfo);

	for (SIZE_T nIndex = (SIZE_T)siSysInfo.lpMinimumApplicationAddress; nIndex < MAX_REL;)
	{
		nQueryBytes = VirtualQuery((LPCVOID)nIndex, &mbiBasicInfo, sizeof(mbiBasicInfo));
		
		IS_ZERO("VirtualQuery", nQueryBytes, lbl_cleanup);

		if (mbiBasicInfo.State == MEM_FREE && mbiBasicInfo.RegionSize >= siSysInfo.dwAllocationGranularity)
		{
			pReturnVal = VirtualAlloc(mbiBasicInfo.BaseAddress, ALLOC_JMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (NULL == pReturnVal)
			{
				printf("VirtualAlloc failed! error code: %d\n", GetLastError());
			}
			else
			{
				break;
			}
		}
		
		nIndex = nIndex + mbiBasicInfo.RegionSize;
	}

lbl_cleanup:
	return pReturnVal;
}


BOOL DHOOK_hook(LPVOID lpFuncAddr, LPVOID lpReplaceAddr)
{
	LPVOID pLocAfterOverWrite;

	BOOL bReturnVal = FALSE;
	BOOL bPatch = FALSE;
	BYTE pbJumpByte[PUSH_RET_SIZE] = {0x68, 0x0, 0x0, 0x0, 0x0, 0xC3};

	DHOOK_initGlobalHook(lpFuncAddr, lpReplaceAddr);
	pLocAfterOverWrite = (LPVOID)((SIZE_T)pgHookData->pHookedFunc + PATCH_JMP_SIZE);

	/*Create exit trampoline*/
	pgHookData->pExitTramp = DHOOK_allocTrampoline();

	/*Patch the function we want to hook to the replacement function*/
	bPatch = DHOOK_patchAPI(pgHookData->pHookedFunc, pgHookData->pReplacmentFunc, &pgHookData->pbOverWritten);
	IS_ZERO("DHOOK_patchAPI", bPatch, lbl_cleanup);

	/*Copy prologue to exit trampoline*/
	memcpy_s(pgHookData->pExitTramp, ALLOC_JMP_SIZE, pgHookData->pbOverWritten, PATCH_JMP_SIZE);

	/*Copy push ret to rest of the trampoline*/
	memcpy_s(pbJumpByte + 1, PATCH_JMP_SIZE, &(pLocAfterOverWrite), sizeof(pgHookData->pHookedFunc));
	memcpy_s((LPBYTE)pgHookData->pExitTramp + PATCH_JMP_SIZE, ALLOC_JMP_SIZE-PATCH_JMP_SIZE, pbJumpByte, PUSH_RET_SIZE);

	bReturnVal = TRUE;

lbl_cleanup:
	return bReturnVal;
}

BOOL DHOOK_unhook()
{
	BOOL bReturnVal = FALSE;
	BOOL bGenericBool = FALSE;
	DWORD dwOldProtect = 0;
	HANDLE hProcessHandle = FALSE;

	/*Prepare hooked page for overwrite*/
	bGenericBool = VirtualProtect(pgHookData->pHookedFunc, PATCH_JMP_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	IS_ZERO("VirtualProtect", bGenericBool, lbl_cleanup);

	/*Overwrite data*/
	memcpy_s(pgHookData->pHookedFunc, PATCH_JMP_SIZE, pgHookData->pbOverWritten, PATCH_JMP_SIZE);

	/*Return to previous paging protection*/
	bGenericBool = VirtualProtect(pgHookData->pHookedFunc, PATCH_JMP_SIZE, dwOldProtect, &dwOldProtect);

	IS_ZERO("VirtualProtect", bGenericBool, lbl_cleanup);

	hProcessHandle = GetCurrentProcess();

	IS_ZERO("GetCurrentProcess", hProcessHandle, lbl_cleanup);

	bGenericBool = FlushInstructionCache(hProcessHandle, pgHookData->pHookedFunc, PATCH_JMP_SIZE);

	IS_ZERO("FlushInstructionCache", bGenericBool, lbl_cleanup);

	bReturnVal = TRUE;

lbl_cleanup:
	SAFE_FREE(pgHookData);
	return bReturnVal;
}


INT WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType)
{	
	lpText = "DAT BOI GOT HOOKEDDD!";

	OldMessageBoxA pMsgBoxA = (OldMessageBoxA)pgHookData->pExitTramp;

	return pMsgBoxA(hWnd, lpText, lpCaption, uType);
}
