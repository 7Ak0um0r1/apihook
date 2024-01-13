#include <Windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	HMODULE user32 = LoadLibrary("user32.dll");
	FARPROC pMessageBox = GetProcAddress(user32, "MessageBoxA");

	pMessageBox(NULL, "hello world", "main", MB_OK);
	FreeLibrary(user32);

	return 0;
}

