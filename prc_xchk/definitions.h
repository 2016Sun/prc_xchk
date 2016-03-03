#pragma once

#include "stdafx.h"
#include <Winternl.h>



//////////////////////////////////////////////////////////////////////////////


// Below definitions are copied from http://undocumented.ntinternals.net/



//:::::::::::::::::::::::::::::::::::::;
typedef struct _SYSTEM_THREAD 
{
	LARGE_INTEGER	KernelTime;			// Sum of thread's execution time in KernelMode, in native format.
	LARGE_INTEGER	UserTime;			// Sum of thread's execution time in UserMode, in native format.
	LARGE_INTEGER	CreateTime;			// Time of thread creation, in native format.
	ULONG			WaitTime;			// Sum of thread's waiting time, in native format.
	PVOID			StartAddress;		// Thread start address.
/*CLIENT_ID*/	char		ClientId[8];			// Process and thread identyficators.
/*KPRIORITY*/	DWORD		Priority;			// Thread Priority.
	LONG			BasePriority;		// Thread base Priority.
	ULONG			ContextSwitchCount;	// Number of context switches executed by thread.
	ULONG			State;				// Current thread's state.
/*KWAIT_REASON*/ DWORD	WaitReason;			// Reason for waiting (if any). 

} SYSTEM_THREAD, *PSYSTEM_THREAD;
 

//:::::::::::::::::::::::::::::::::::::;
typedef struct _SYSTEM_PROCESS_INFORMATION2 
{
	ULONG			NextEntryOffset;		// Offset from begining of output buffer to next process entry. 
											// On last entry contains zero.
	ULONG			NumberOfThreads;		// Number of process'es threads. 
											// Also number of members in Threads array descripted below.
	LARGE_INTEGER	Reserved[3];			// Reserved. 
	LARGE_INTEGER	CreateTime;				// Process creation time, in 100-ns units.
	LARGE_INTEGER	UserTime;				// Effective time in User Mode.
	LARGE_INTEGER	KernelTime;				// Effective time in Kernel Mode.
	UNICODE_STRING	ImageName;				// Process name, based on executable file name.
/*KPRIORITY*/	DWORD		BasePriority;			// Process base priority.
	HANDLE			ProcessId;				// Unique identifier of process.
	HANDLE			InheritedFromProcessId;	// Creator's identifier. 
	ULONG			HandleCount;			// Nr of open HANDLEs.
	ULONG			Reserved2[2];			// Reserved.
	ULONG			PrivatePageCount;		// Number of memory pages assigned to process. 
/*VM_COUNTERS*/ DWORD		VirtualMemoryCounters;	// Memory performance counters. 
/*IO_COUNTERS*/ DWORD		IoCounters;				// IO performance counters.
	SYSTEM_THREAD	Threads[0];				// Array of SYSTEM_THREAD structures descripting 
											// process's threads.
} SYSTEM_PROCESS_INFORMATION2, *PSYSTEM_PROCESS_INFORMATION2;


//:::::::::::::::::::::::::::::::::::::;
typedef struct _SYSTEM_HANDLE_ENTRY 
{
    ULONG			OwnerPid;		// ProcessID of handle owner
    BYTE			ObjectType;		// Type of handle (i.e. HANDLE_TYPE_PROCESS)
    BYTE			HandleFlags;	// 
    USHORT			HandleValue;	// Handle value
    PVOID			ObjectPointer;	// 
    ACCESS_MASK		GrantedAccess;	// Security attributes
} SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY ;
 
typedef struct _SYSTEM_HANDLE_INFORMATION 
{
    ULONG				HandleCount;	// Number of found handles
    SYSTEM_HANDLE_ENTRY Handles[1];		// SYSTEM_HANDLE_ENTRY structures table ( 1 means nothing)
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION ;



//:::::::::::::::::::::::::::::::::::::;		-- structure for SystemSessionProcessInformation (53)
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG BufferLength;
    PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;


//::::::::::::::::::::::::::::::::::::::

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
/*CLIENT_ID*/ LONG ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebAddress; /* This is only filled in on Vista and above */
    ULONG Reserved1;
    ULONG Reserved2;
    ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
/*KPRIORITY*/ DWORD BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID PageDirectoryBase;
/*VM_COUNTERS*/ LONG VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
/*IO_COUNTERS*/ LONG IoCounters;
    SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_EXTENDED_PROCESS_INFORMATION, *PSYSTEM_EXTENDED_PROCESS_INFORMATION;




