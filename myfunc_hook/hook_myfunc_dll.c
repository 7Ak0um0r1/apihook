#include <Windows.h>
#include <Dbghelp.h>
#include <stdio.h>
#pragma comment(lib, "Dbghelp")

int mymyFunc(int a);

int modifyIAT (char *targetDll, char *targetFunc) {
    HMODULE hModule = GetModuleHandle(NULL);
    ULONG buf;
    HMODULE kernel32 = GetModuleHandle(targetDll);
    FARPROC origSleep = GetProcAddress(kernel32, targetFunc);

    PIMAGE_IMPORT_DESCRIPTOR iidesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &buf, NULL);
    if (iidesc == NULL) {
        return 1;
    }

    for (; iidesc->Name; iidesc++) {
        char dbgstr[128];
        if (strcmp((const char *)hModule+iidesc->Name, targetDll) == 0) {
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((PBYTE)hModule + iidesc->FirstThunk);
            for (; iat->u1.Function; iat++) {
                if (iat->u1.Function == (DWORD)origSleep) {
                    DWORD tmp;
                    VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), PAGE_WRITECOPY, &tmp);
                    iat->u1.Function = (DWORD)mymyFunc;
                    VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), tmp, &tmp);
                }
            }
        }
    }

    return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        char *targetDll = "mydll1.dll";
        char *targetFunc = "myFunc";

        int result = modifyIAT(targetDll, targetFunc);
        if (result != 0) {
            char dbgstr[128];
            sprintf(dbgstr, "Failed modifyIAT (%d)\n", result);
            OutputDebugString(dbgstr);
        }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

int mymyFunc(int a)
{
    OutputDebugString("hooked api!\n");
    return a - 1;
}
