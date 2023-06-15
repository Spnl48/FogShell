#pragma once


#include <Windows.h>
#include <stdio.h>
#include "utiles.h"
// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {


	char Output0[32], Output1[32], Output2[32], Output3[32];

	char result[128];
	sprintf_s(Output0, sizeof(Output0), "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);
	sprintf_s(Output1, sizeof(Output1), "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);
	sprintf_s(Output2, sizeof(Output2), "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);
	sprintf_s(Output3, sizeof(Output3), "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);
	sprintf_s(result, sizeof(result), "%s-%s-%s%s", Output0, Output1, Output2, Output3);


	return (char*)result;
}


BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (ShellcodeSize % 16 != 0) {
		printf("[-] The Shellcode size is not Multiple by 16 \n");
		AppendShellcode(16, ShellcodeSize, pShellcode);;
	}
	printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));


	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the UUID string
		if (c == 16) {
			counter++;

			// Generating the UUID string from 16 bytes which begin at i until [i + 15]
			UUID = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				printf("\"%s\"", UUID);
				break;
			}
			else {
				printf("\"%s\", ", UUID);
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