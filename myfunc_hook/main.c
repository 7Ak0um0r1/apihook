#include <Windows.h>
#include <stdio.h>

extern __declspec(dllimport) int myFunc(int);

int main(int argc, char *argv[])
{
	while (1) {
        printf("data: %d\n", myFunc(5));
		Sleep(1000);
	}
}

