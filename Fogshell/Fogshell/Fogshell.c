#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "utiles.h"
#include "Ipv4.h"
#include "Ipv6.h"
#include "UUID.h"




int printUsage(char* MeLocation) {
	printf("[!] Usage: %s <payload file path> [Option]\n", MeLocation);
	printf("[i] Option Can Be : \n");
	printf("\n\t[1] \"Ipv4Fuscation\" || \"ipv4\" ");
	printf("\n\t[2] \"Ipv6Fuscation\" || \"ipv6\" ");
	printf("\n\t[3] \"UUIDFuscation\" || \"uuid\" ");
	printf("\n");
	printf("[i] ");
	system("PAUSE");
	return -1;
}


int main(int argc, char* argv[])
{


	// args check:
	if (argc != 3) {
		return printUsage(argv[0]);
	}

	if ((!ReadBinFile(argv[1])) || PayloadData.pShell == NULL || PayloadData.BytesNumber == NULL) {
		system("PAUSE");
		return -1;
	}
	printf("[i] Size Of Shellcode: %ld \n", (unsigned int)PayloadData.BytesNumber);

	if (strcmp(argv[2], "Ipv4Fuscation") == 0 || strcmp(argv[2], "ipv4fuscation") == 0 || strcmp(argv[2], "ipv4") == 0 || strcmp(argv[2], "IPV4") == 0) {

		// Generate the IPv4 representation of the shellcode
		GenerateIpv4Output(PayloadData.pShell, (unsigned int)PayloadData.BytesNumber);
	}
	else if (strcmp(argv[2], "Ipv6Fuscation") == 0 || strcmp(argv[2], "ipv6fuscation") == 0 || strcmp(argv[2], "ipv6") == 0 || strcmp(argv[2], "IPV6") == 0) {
		GenerateIpv6Output(PayloadData.pShell, (unsigned int)PayloadData.BytesNumber);
	}
	else if (strcmp(argv[2], "uuidFuscation") == 0 || strcmp(argv[2], "UUIDfuscation") == 0 || strcmp(argv[2], "uuid") == 0 || strcmp(argv[2], "UUID") == 0) {
		GenerateUuidOutput(PayloadData.pShell, (unsigned int)PayloadData.BytesNumber);

	}
	else {
		printf("[!] Unkown Input : %s \n", argv[2]);
		return printUsage(argv[0]);
	}


	return 0;
}

