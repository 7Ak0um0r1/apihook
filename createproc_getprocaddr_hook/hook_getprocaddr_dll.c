#include <Windows.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <tchar.h>
#pragma comment(lib, "Dbghelp")
#pragma comment(lib, "User32.lib")

typedef FARPROC(WINAPI* TYPEGETPROCADDRESS)(HMODULE hModule, LPCSTR lpProcName);
TYPEGETPROCADDRESS fnGetProcAddress = NULL;

BOOL is_hooked = FALSE;

FARPROC __stdcall myGetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName
);

int __stdcall myMessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
);

int modifyIAT(const _TCHAR* targetDll, const char* targetFunc) {
    HMODULE hModule = GetModuleHandle(NULL);
    ULONG buf;
    HMODULE kernel32;
    if (targetDll == NULL) {
        return -1;
    }
    else {
        kernel32 = GetModuleHandle(targetDll);
    }

    FARPROC origSleep;
    if (kernel32 == NULL) {
        return -1;
    }
    else {
        OutputDebugStringA(targetFunc);
        origSleep = GetProcAddress(kernel32, targetFunc);
    }

    PIMAGE_IMPORT_DESCRIPTOR iidesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &buf, NULL);
    if (iidesc == NULL) {
        return 1;
    }

    for (; iidesc->Name; iidesc++) {
        if (lstrcmp((const _TCHAR*)hModule + iidesc->Name, targetDll) == 0) {
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((PBYTE)hModule + iidesc->FirstThunk);
            for (; iat->u1.Function; iat++) {
                if (iat->u1.Function == (DWORD)origSleep) {
                    DWORD tmp;
                    VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), PAGE_WRITECOPY, &tmp);
                    iat->u1.Function = (DWORD)myGetProcAddress;
                    VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), tmp, &tmp);
                }
            }
        }
    }

    return 0;
}
BOOL WINAPI DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    const _TCHAR* targetDll = _T("KERNEL32.dll");
    const char* targetFunc = "GetProcAddress";

    int result = 0;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        if (!is_hooked) {
            HMODULE hModule = LoadLibraryA("KERNEL32.dll");
	        fnGetProcAddress = (TYPEGETPROCADDRESS)GetProcAddress(hModule, "GetProcAddress"); 
            result = modifyIAT(targetDll, targetFunc);
            is_hooked = TRUE;
            OutputDebugString(_T("hooked!\n"));
        }
        if (result != 0) {
            _TCHAR dbgstr[128];
            _stprintf_s(dbgstr, 128, _T("Failed modifyIAT (%d)\n"), result);
            OutputDebugString(dbgstr);
        }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

FARPROC __stdcall myGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    char dbgstr[128];
    sprintf_s(dbgstr, 128, "hooked api2: %s\n", lpProcName);
    OutputDebugStringA(dbgstr);
    if (strcmp(lpProcName, "MessageBoxA") == 0) {
        OutputDebugString(_T("detect\n"));
        return (FARPROC)myMessageBoxA;
    }
    //return GetProcAddress(hModule, lpProcName);
    return fnGetProcAddress(hModule, lpProcName);
}

int __stdcall myMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    OutputDebugString(_T("hooked api3!\n"));
    return MessageBoxA(hWnd, "hooked!", lpCaption, uType);
}
