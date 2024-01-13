#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "User32.lib")

int main(int argc, char *argv[])
{
	MessageBox(NULL, "hello world", "main", MB_OK);

	return 0;
}

