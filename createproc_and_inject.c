#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

int main(int argc, _TCHAR* argv[])
{
    if (argc != 3) {
        printf("usage: inject.exe <exe> <dll>");
        return 1;
    }

    _TCHAR* exePath = argv[1];
    _TCHAR* dllPath = argv[2];

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcess(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Failed CreateProcess");
        return 1;
    }
    printf("CreateProcess OK\n");


    // virtualallocex: PROCESS_VM_OPERATION
    // writeprocessmemory: PROCESS_VM_WRITEおよびPROCESS_VM_OPERATION
    /*
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed OpenProcess\n");
        return 1;
    }
    */

    HANDLE hProcess = pi.hProcess;
    printf("GetCurrentProcess OK\n");

    LPVOID buf = VirtualAllocEx(hProcess, NULL, lstrlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf == NULL) {
        printf("Failed VirtualAllocEx\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, buf, dllPath, lstrlen(dllPath) + 1, NULL)) {
        printf("Failed WriteProcessMemory");
        VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    _TCHAR* kernel_module = _T("kernel32");
    HMODULE hModule = GetModuleHandle(kernel_module);
    if (hModule == NULL) {
        printf("Failed GetModuleHandle");
        VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    FARPROC addr = GetProcAddress(hModule, "LoadLibraryA");
    if (addr == NULL) {
        printf("Failed GetProcAddress");
        VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, buf, 0, NULL);
    if (hThread == NULL) {
        printf("Failed CreateRemoteThread\n");
        VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, INFINITE)) {
        printf("Failed WaitForSingleObject\n");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    if (ResumeThread(pi.hThread) == -1) {
        printf("Failed ResumeThread");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(pi.hThread, INFINITE);

    printf("end\n");
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}