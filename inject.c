#include <Windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("usage: xxx.exe <pid> <dll>");
        return 1;
    }

    int pid = atoi(argv[1]);
    if (pid == 0) {
        printf("invalid pid\n");
        return 1;
    }

    char *dllPath = argv[2];

    // virtualallocex: PROCESS_VM_OPERATION
    // writeprocessmemory: PROCESS_VM_WRITEおよびPROCESS_VM_OPERATION
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("Failed OpenProcess\n");
        return 1;
    }

    LPVOID buf = VirtualAllocEx(hProcess, NULL, strlen(dllPath)+1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf == NULL) {
        printf("Failed VirtualAllocEx\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (0 == WriteProcessMemory(hProcess, buf, dllPath, strlen(dllPath)+1, NULL)) {
        printf("Failed WriteProcessMemory");
        VirtualFreeEx(hProcess, buf, strlen(dllPath), MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HMODULE hModule = GetModuleHandle("kernel32");
    if (hModule == NULL) {
        printf("Failed GetModuleHandle");
        VirtualFreeEx(hProcess, buf, strlen(dllPath), MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    FARPROC addr = GetProcAddress(hModule, "LoadLibraryA");
    if (addr == NULL) {
        printf("Failed GetProcAddress");
        VirtualFreeEx(hProcess, buf, strlen(dllPath), MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
 
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, buf, 0, NULL);
    if (hThread == NULL) {
        printf("Failed CreateRemoteThread\n");
        VirtualFreeEx(hProcess, buf, strlen(dllPath), MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    if (WAIT_OBJECT_0 != WaitForSingleObject(hThread, INFINITE)) {
        printf("Failed WaitForSingleObject\n");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, buf, strlen(dllPath), MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("end\n");
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, buf, strlen(dllPath), MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}