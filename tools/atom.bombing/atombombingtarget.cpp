#include "stdafx.h"
#include <Windows.h>

int _tmain(int argc, _TCHAR* argv[])
{
	MessageBoxA(0, "Atombombing Target Process", "Close me before launching the atom bomb!", 0);
	while (true)
		SleepEx(INFINITE, true);
	return 0;
}
