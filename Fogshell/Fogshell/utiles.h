#pragma once
#include <Windows.h>
#include <stdio.h>

typedef struct MyStruct {
	SIZE_T BytesNumber; // number of bytes read from the file 
	PVOID pShell;       // pointer to the shellcode read (here it is not appended) 
};

struct MyStruct PayloadData = { 0 };

//	Function Used To Read The Shellcode.bin File, Save the size of the shellcode and the Pointer To its Buffer in our struct.
BOOL ReadBinFile(char* FileInput) {
	HANDLE hFile;
	DWORD FileSize, lpNumberOfBytesRead;
	BOOL Succ;
	PVOID DllBytes;
	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error: [%d]\n", GetLastError());
		return FALSE;
	}
	FileSize = GetFileSize(hFile, NULL);
	DllBytes = malloc((SIZE_T)FileSize);
	Succ = ReadFile(hFile, DllBytes, FileSize, &lpNumberOfBytesRead, NULL);
	if (!Succ) {
		printf("[!] ReadFile Failed With Error:\n", GetLastError());
		return FALSE;
	}
	PayloadData.BytesNumber = (SIZE_T)lpNumberOfBytesRead;
	PayloadData.pShell = DllBytes;
	CloseHandle(hFile);
	return TRUE;
}


// used to round up 'numToRound' to be multiple of 'multiple'
// in ipv4 : multiple = 4
int roundUp(int numToRound, int multiple) {
	if (multiple == 0) {
		return numToRound;
	}
	int remainder = numToRound % multiple;
	if (remainder == 0) {
		return numToRound;
	}
	return numToRound + multiple - remainder;
}


// used to appened the shellcode with nops ant the end, the nops are added of size 'n'
void AppendShellcode(int n, SIZE_T ShellcodeSize, PVOID pshell) {
	unsigned char Nop[1] = { 0x90 };
	int MultipleByn, HowManyToAdd;
	PVOID NewPaddedShellcode;

	MultipleByn = roundUp(ShellcodeSize, n);
	printf("[+] Constructing the Shellcode To Be Multiple Of %d, Target Size: %d \n", n, MultipleByn);
	HowManyToAdd = MultipleByn - ShellcodeSize;
	NewPaddedShellcode = malloc(ShellcodeSize + HowManyToAdd + 1);
	memcpy(NewPaddedShellcode, pshell, ShellcodeSize);
	int i = 0;
	while (i != HowManyToAdd) {
		memcpy(((ULONG_PTR)NewPaddedShellcode + ShellcodeSize + i), Nop, 1);
		i++;
	}
	printf("[+] Added : %d \n", i);
	SIZE_T FinalSize = ShellcodeSize + HowManyToAdd;
	pshell = NewPaddedShellcode;
}