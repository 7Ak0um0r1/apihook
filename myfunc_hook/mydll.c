#include <Windows.h>

__declspec(dllexport) int myFunc(int a)
{
    return a + 1;
}