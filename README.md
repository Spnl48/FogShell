"# FogShell" 

advanced payload obfuscation techniques, some of which are being used in the wild, such as in Hive ransomware.
reason to use this tools, to evade windows defender staticly using shellcode obfuscation techniques.

Fogshell Supports 3 types of obfuscated shellcode output, all as arrays:
Ipv4Fuscation: Output The Shellcode As A Array Of ipv4 Addresses [Example: 252.72.131.228]
Ipv6Fuscation: Output The Shellcode As A Array Of ipv6 Addresses [Example: FC48:83E4:F0E8:C000:0000:4151:4150:5251]
UuidFuscation: Output The Shellcode As A Array Of alphanumeric string [Example: E48348FC-E8F0-00C0-0000-415141505251]

Running The binary as is, will output the help screen, from there it is so easy to use, i added 3 other projects, to demonstrate how to call the decoder function.
Fogshell will output on the console the shellcode as well the SizeofShellcode and NumberofElements needed for decryption.

Note: The projects should be compiled in release mode. Compiling in debug mode will result in the binary not working correctly.

The Help Screen:
![image](https://github.com/Spnl48/FogShell/assets/68971838/ff509b78-283b-4d11-bde6-0f0193aa65e3)

Example:
![image](https://github.com/Spnl48/FogShell/assets/68971838/24bd0a63-897f-4eb3-b41d-9939ae10ad3d)

![image](https://github.com/Spnl48/FogShell/assets/68971838/92ea32c0-d937-4eb8-a8b2-f337b96e4993)

