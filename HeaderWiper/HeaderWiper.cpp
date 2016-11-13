// HeaderWiper.cpp : Defines the entry point for the console application.
//
#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <string>

int main()
{
	bool bProtect = FALSE;
	DWORD dwBaseAddress = (DWORD)GetModuleHandle(NULL);
	DWORD dwIt = 0;
	DWORD dwProtect = 0;
	DWORD dwSizeOfHeaders = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dwBaseAddress;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	std::string name;
	std::cout << "Press enter to continue...";
	std::getline(std::cin, name);

	// Check for MZ Header
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0x4d5a;
	}

	// Check for PE Header
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 0x5000;
	}

	if (pNtHeader->FileHeader.SizeOfOptionalHeader) {
		// Get Size of Headers
		dwSizeOfHeaders = pNtHeader->OptionalHeader.SizeOfHeaders;

		// Make the Page writeable
		bProtect = VirtualProtect((LPVOID)dwBaseAddress, dwSizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwProtect);
		if (FALSE == bProtect) {
			return GetLastError();
		}

		// Wipe PE/MZ Header
		RtlZeroMemory((PVOID)dwBaseAddress, dwSizeOfHeaders);

		// Restore original page permissions
		bProtect = VirtualProtect((LPVOID)dwBaseAddress, dwSizeOfHeaders, dwProtect, &dwProtect);
		if (FALSE == bProtect) {
			return GetLastError();
		}
	}

	do {
		Sleep(1);
	} while (1);

    return ERROR_SUCCESS;
}

