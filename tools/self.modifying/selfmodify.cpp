// selfModifyingCode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"


void funca(int a) {

	if (a > 1){
		funca(--a);
	}
	int i = 0;
	i++;
	printf("a: %d\n", a);
	printf("i: %d\n", i);
}


int _tmain(int argc, _TCHAR* argv[])
{
	int arg;
	#ifdef _M_AMD64
	arg = 45;
	#else
	arg = 37;
	#endif

	funca(5);
	printf("Before modification\n");
	void *funca_addr = (void*)funca;
	printf("funca address: %p\n", funca_addr);
	DWORD oldProtection;
	MEMORY_BASIC_INFORMATION basic_info;
	basic_info.Protect = 0x99999999;
	printf("[++] Test: %x.\n", basic_info.Protect);
	SIZE_T returnValue;
	//LPVOID temp = &lpRemoteLibraryBuffer - 4096;
	returnValue = VirtualQuery(funca_addr, &basic_info, sizeof(MEMORY_BASIC_INFORMATION));

	if (returnValue > 0) {
		printf("[++] Initial Protection for vad: %#02x.\n", basic_info.AllocationProtect);
		printf("[++] Current Protection for function: %#02x.\n", basic_info.Protect);
	}
	getchar();
	VirtualProtect(funca_addr, 4096, PAGE_EXECUTE_WRITECOPY, &oldProtection);
	returnValue = VirtualQuery(funca_addr, &basic_info, sizeof(MEMORY_BASIC_INFORMATION));
	printf("After page protection change\n");

	if (returnValue > 0) {
		printf("[++] Initial Protection for vad: %#02x.\n", basic_info.AllocationProtect);
		printf("[++] Current Protection for function: %#02x.\n", basic_info.Protect);
	}
	getchar();
	unsigned char *instruction = (unsigned char*)funca_addr + arg;
	printf("instruction address: %p\n", instruction);
	*instruction = 0x2A;

	returnValue = VirtualQuery(funca_addr, &basic_info, sizeof(MEMORY_BASIC_INFORMATION));
	printf("After modification\n");

	if (returnValue > 0) {
		printf("[++] Initial Protection for vad: %#02x.\n", basic_info.AllocationProtect);
		printf("[++] Current Protection for function: %#02x.\n", basic_info.Protect);
	}

	printf("Before running funca again\n");
	getchar();
	funca(3);
	printf("Before shrinking\n");
	getchar();
	SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
	printf("Before exit\n");
	getchar();
	return 0;
}


