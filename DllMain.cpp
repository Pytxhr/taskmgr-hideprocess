#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <MinHook.h>
#include <stdio.h>

#define STATUS_SUCCESS 0
#if defined _M_X64
#pragma comment(lib, "libMinHook-x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86.lib")
#endif

byte* GetFunctionAddress(const char* szModule, const char* szFunction)
{
	HMODULE hMod = GetModuleHandleA(szModule);
	if (hMod == 0)
		return 0;

	return reinterpret_cast<byte*>(GetProcAddress(hMod, szFunction));
}

using fnQuerySystemInformation = NTSTATUS(WINAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

fnQuerySystemInformation oQuerySystemInformation = 0;

NTSTATUS WINAPI hkNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
)
{
	NTSTATUS originalReturn = oQuerySystemInformation(
		SystemInformationClass, 
		SystemInformation, 
		SystemInformationLength, 
		ReturnLength
	);

	if (SystemInformationClass == SystemProcessInformation && originalReturn == STATUS_SUCCESS)
	{
		SYSTEM_PROCESS_INFORMATION* pCurrent = nullptr;
		SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)(SystemInformation);

		//Walk the linked list of processes, looking for our application's name
		do
		{
			pCurrent = pNext;
			pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
			if (!_wcsnicmp(pNext->ImageName.Buffer, L"Not a cheat.exe", pNext->ImageName.Length))
			{
				//If our proof of concept application is at the end of the list
				if (!pNext->NextEntryOffset)
					pCurrent->NextEntryOffset = 0;
				else //Just skip our entry, making Task Manager not see this app.
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
			}
		} while (pCurrent->NextEntryOffset != NULL);
	}

	return originalReturn;
}

DWORD WINAPI Main(LPVOID lpDLL)
{
	//Initialize the hooking library I'm using (MinHook)
	if (MH_Initialize() != MH_OK)
	{
		MessageBoxA(0, "MinHook couldn't initialize.", "Unexpected error", MB_OK | MB_ICONERROR);
		FreeLibraryAndExitThread((HMODULE)lpDLL, 0);
		return 0;
	}

	//Find the function required to spoof Task Manager
	fnQuerySystemInformation pQuerySystemInformation = (fnQuerySystemInformation)GetFunctionAddress("ntdll.dll", "NtQuerySystemInformation");

	//If we didn't find it (sad)
	if (pQuerySystemInformation == 0)
	{
		MessageBoxA(0, "The function was not found.", "Unexpected error", MB_OK | MB_ICONERROR);
		MH_Uninitialize();
		FreeLibraryAndExitThread((HMODULE)lpDLL, 0);
		return 0;
	}
	
	//Create the hook
	MH_CreateHook((LPVOID)pQuerySystemInformation, hkNtQuerySystemInformation, (void**)&oQuerySystemInformation);
	
	//Enable the hook
	MH_EnableHook(MH_ALL_HOOKS);
	return 1;
}


#define DLL_EXPORT extern "C" __declspec(dllexport)
DLL_EXPORT BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, Main, hinstDLL, 0, 0);
	}

	return true;
}