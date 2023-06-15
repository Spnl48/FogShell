#pragma once
#include <Windows.h>
#include <stdio.h>
#include "utiles.h"

// Function takes in 16 raw bytes and returns them in an IPv6 address string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each IPv6 segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in an IPv6 (32 * 4 = 128)
	char result[128];
	sprintf_s(Output0, sizeof(Output0), "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);
	sprintf_s(Output1, sizeof(Output1), "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);
	sprintf_s(Output2, sizeof(Output2), "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);
	sprintf_s(Output3, sizeof(Output3), "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);
	sprintf_s(result, sizeof(result), "%s:%s:%s:%s", Output0, Output1, Output2, Output3);



	return (char*)result;
}



BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (ShellcodeSize % 16 != 0) {
		printf(" [-] The Shellcode size is not Multiple by 16 \n");
		AppendShellcode(16, ShellcodeSize, pShellcode);
	}
	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));
	int c = 16, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		if (c == 16) {
			counter++;

			// Generating the IPv6 address from 16 bytes which begin at i until [i + 15]
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last IPv6 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv6 address
				printf("\"%s\", ", IP);
			}
			c = 1;
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}