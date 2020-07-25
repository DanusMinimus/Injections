#pragma once
/*##############################Includes##########################################*/
#include <stdio.h>
#include <Windows.h>
#include "common.h"

/*##############################Macros#########################################*/
#define TypeDefWINAPI(_procname, _typedef, ...) \
	typedef _typedef (WINAPI* _procname)(__VA_ARGS__); \

#define CreateWINAPI(_procname, _typedef, _procaddr, ...) \
	_typedef(WINAPI* _procname)(__VA_ARGS__) = (_typedef(WINAPI* )(__VA_ARGS__))_procaddr; \

#define CallWINAPI(_procname, ...) \
	_procname(__VA_ARGS__);

#if _WIN32 || _WIN64
	#if _WIN64
		#define SYS_TYPE 0x64
	#else
		#define SYS_TYPE 0x86
		#define MAX_REL 0x7fffffff
	#endif
#endif


/*##############################Typedef#########################################*/
TypeDefWINAPI(OldMessageBoxA, INT, HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType);

/*##############################Constants#########################################*/

#define ALLOC_JMP_SIZE 11
#define PATCH_JMP_SIZE 5
#define PUSH_RET_SIZE 6

/*Restricted opcodes*/
#define JMP 0xE9
#define CALL 0xE8
#define INTC 0xCD
#define RET 0xC3

/*Should I check for these? */
#define SYSCALL 0x0F05 
#define SYSENTER 0x0F34

/*##############################Structure Defentions##############################*/
typedef struct DHOOK_HOOKDATA
{
	LPVOID pExitTramp;
	LPVOID pHookedFunc;
	LPVOID pReplacmentFunc;
	LPBYTE pbOverWritten;
}*PDHOOK_HOOKDATA;

/*##############################Globals##########################################*/
static PDHOOK_HOOKDATA pgHookData;

/*##############################Function Defeneitions##############################*/

/*
This function initializes the global DHOOK

IN lpFuncAddr - The address of the function to hook
IN lpReplaceAddr - The address of the replacement function
*/
VOID DHOOK_initGlobalHook(LPVOID lpFuncAddr, LPVOID lpReplaceAddr);

/*
This function examines an API address and checks if it is safe to hook

IN lpFuncAddr - The address of the function to hook
OUT BOOL - If the function is safe to hook, the function will return TRUE otherwise it will return FALSE
*/
BOOL DHOOK_isSafeToHook(IN LPVOID lpFuncAddr);

/*
This function patches the API

IN lpFuncAddr - The address of the function to hook
IN lpTramp - The address of the trampoline
IN ppbByteArray - An address of a byte pointer array that will contain the overwritten bytes
OUT BOOL - If the patch was successful TRUE is returned, otherwise FALSE is returned.
*/
BOOL DHOOK_patchAPI(IN LPVOID lpFuncAddr, IN LPVOID lpTramp, IN LPBYTE * ppbByteArray);

/*
This function allocates a trampoline

OUT LPVOID - If successful, the function would return the address of the trampoline, otherwise NULL is returned.
*/
LPVOID DHOOK_allocTrampoline();

/*
This function takes an API address and a hook function address and hooks the API

IN lpFuncAddr - The address of the function to hook
IN lpReplaceAddr - The address of the replacement function

OUT BOOL - Success code
*/
BOOL DHOOK_hook(LPVOID lpFuncAddr, LPVOID lpReplaceAddr);

/*
This function takes an API address and unhooks it by rewriting the overwritten data

OUT BOOL - Success code
*/
BOOL DHOOK_unhook();

/*
Test function
*/
INT WINAPI NewMessageBoxA(HWND hWnd, LPCSTR lpText, LPCTSTR lpCaption, UINT uType);

