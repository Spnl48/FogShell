#pragma once


#define _CRT_SECURE_NO_WARNINGS


#include <Windows.h>
#include <stdio.h>

#include "utiles.h"

// Function takes in 4 raw bytes and returns them in an IPv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output[32];

	// Creating the IPv4 address and saving it to the 'Output' variable
	sprintf_s(Output, sizeof(Output), "%d.%d.%d.%d", a, b, c, d);


	// printf("[i] Output: %s\n", Output);
	return (char*)Output;
}

// Generate the IPv4 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
void GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {



	// If the shellcode buffer is not a multiple of 4
	if (ShellcodeSize % 4 != 0) {

		printf("The Shellcode size is not Multiple by 4\n");
		AppendShellcode(4, ShellcodeSize, pShellcode);
	}
	printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));

	// We will read one shellcode byte at a time, when the total is 4, begin generating the IPv4 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 4.
	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 4 we enter this if statement to begin generating the IPv4 address
		if (c == 4) {
			counter++;

			// Generating the IPv4 address from 4 bytes which begin at i until [i + 3]
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

			// Printing the last IPv4 address
			if (i == ShellcodeSize - 4) {
				printf("\"%s\"", IP);
				break;
			}
			else {
				printf("\"%s\", ", IP);
			}

			c = 1;
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");

}



