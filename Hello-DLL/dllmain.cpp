#include <windows.h>


VOID Hello()
{

	for (int i = 0; i < 10000; i++) {
		MessageBoxW(NULL, L"[+] ^^", L"[*] hello stupid!!!", MB_OK);
	}

}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Hello();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
