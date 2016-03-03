# prc_xchk

User-mode process cross-checking utility, intended to hunt for naive malware hiding itself by hooking user-mode routines (by means of IAT/EAT). Program utilizes couple of methods to perform processes collection and then attempts to cross-check them.

Date: 2009-2011.

## Usage

Simply, start the app by issuing:

```
> prc_xchk.exe

        Process-list cross-checking and native API hook testing security tool.
PRC_XCHK v0.2   OSVer:  6.2.9200        MGeeky's bench '09, mgeeky@gmail.com

Hidden processes scanner with simple/naive native API hooks tester.


[1] ToolHlp stage...                                    Result: 125 PIDs found.
[2] PSAPI stage...                                      Result: 125 PIDs found.
[3] NtQuerySystemInformation #1...                      Result: 124 PIDs found.
[4] NtQuerySystemInformation #2...                      Result: 125 PIDs found.
[5] Searching inside CSRSS PIDs/handles base...         Result: 2/125 PIDs found
[6] NtQuerySystemInformation #3...
        [!] NtQuerySystemInformation failed: 87 (NTSTATUS: C0000004/24)
[7] NtQuerySystemInformation #4...                      Result: 124 PIDs found.
[8] Brute-force scanning method...      				Result: 126 PIDs found.

        ****   Alternative method scan - using direct system call  ****

[9]  NtQuerySystemInformation #1 (syscall)...[9] NtQuerySystemInformation #1 (syscall)...               
														Result: 0 PIDs found.
[10] NtQuerySystemInformation #2 (syscall)...
        [!] NtQuerySystemInformation failed: 487 (NTSTATUS: 7775D0/317)
[11] NtQuerySystemInformation #4 (syscall)...
        [!] NtQuerySystemInformation failed: 487 (NTSTATUS: 0/0)


                *********************************************

Ordinary sanity checks...

Analysing results...
Checking for any native API Hooks...            System seems to be CLEAR.

                YOURS OPERATING SYSTEM IS (seems to be) HEALTHY !
```

Hereby the program failed in gathering couple of methods since it has been launched from x64 instance of Win10. I've not updated it since the last time (Win7 x86) therefore it was doomed to present results this way.
Hope some day I'll have enough time to sit and fix it properly.