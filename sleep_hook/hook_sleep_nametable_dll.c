#include <Windows.h>
#include <Dbghelp.h>
#include <stdio.h>
#pragma comment(lib, "Dbghelp")

void mySleep(DWORD dwMilliseconds);

int modifyIAT (char *targetDll, char *targetFunc) {
    HMODULE hModule = GetModuleHandle(NULL);
    ULONG buf;
 
    PIMAGE_IMPORT_DESCRIPTOR iidesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &buf, NULL);
    if (iidesc == NULL) {
        return 1;
    }

    for (; iidesc->Name; iidesc++) {
        char dbgstr[128];
        if (strcmp((const char *)hModule+iidesc->Name, targetDll) == 0) {
            PIMAGE_THUNK_DATA addressTable = (PIMAGE_THUNK_DATA)((PBYTE)hModule + iidesc->FirstThunk);
            PIMAGE_THUNK_DATA nameTable = (PIMAGE_THUNK_DATA)((PBYTE)hModule + iidesc->OriginalFirstThunk);
            for (; addressTable->u1.Function; addressTable++, nameTable++) {
                PIMAGE_IMPORT_BY_NAME names = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + nameTable->u1.AddressOfData);
                if (strcmp(names->Name, targetFunc) == 0) {
                    DWORD tmp;
                    VirtualProtect(&addressTable->u1.Function, sizeof(addressTable->u1.Function), PAGE_WRITECOPY, &tmp);
                    addressTable->u1.Function = (DWORD)mySleep;
                    VirtualProtect(&addressTable->u1.Function, sizeof(addressTable->u1.Function), tmp, &tmp);
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
        char *targetDll = "KERNEL32.dll";
        char *targetFunc = "Sleep";

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

void mySleep(DWORD dwMilliseconds)
{
    OutputDebugString("hooked api!\n");
    Sleep(dwMilliseconds + 4000);
}
