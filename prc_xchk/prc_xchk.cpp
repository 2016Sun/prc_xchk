// prc_xchk.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <Tlhelp32.h>
#include <Winternl.h>
#include <winver.h>

#include "definitions.h"

#pragma comment(lib,"PSAPI.LIB")


#define MAX_PROCESSES		256
#define NUMBER_OF_STAGES	12


#if _WIN32_WINNT == _WIN32_WINNT_WINXP || _WIN32_WINNT == _WIN32_WINNT_WIN2K
	#define	HANDLE_TYPE_PROCESS	5
#elif _WIN32_WINNT == _WIN32_WINNT_LONGHORN /* Vista */
	#define HANDLE_TYPE_PROCESS	6
#endif

#define NT_SUCCESS(Status)  (((Status >= 0 && Status <= 0x7FFFFFFF)? true:false))


//////////////////////////////////////////////////////////////////////////////

DWORD		g_dwPIDs[ NUMBER_OF_STAGES][ MAX_PROCESSES];
DWORD		g_dwNumOfProcs[ NUMBER_OF_STAGES] = { 0 };


#if _WIN32_WINNT < _WIN32_WINNT_LONGHORN
							// Windows is earlier than Vista Longhorn
	DWORD		g_dwCSRSS_PID = 0;		// There is only one instance of CSRSS.EXE process

#elif _WIN32_WINNT == _WIN32_WINNT_LONGHORN		/* Vista */
	DWORD		g_dwCSRSS_PID[ 3] = { 0xFFFF };	// There can be several currently working CSRSS.EXE
							// processes because of possibility of logged in 
#endif							// several users at once (Switch User capability)

// External thunks
typedef		DWORD ( __stdcall *NTQSI)
					 ( /*SYSTEM_INFORMATION_CLASS*/ DWORD, PVOID, ULONG ,PULONG );
NTQSI		pNtQuerySystemInformation;
typedef		ULONG (__stdcall *RNSTDE)( NTSTATUS);
RNSTDE		_RtlNtStatusToDosError;

DWORD		g_shOSVersionMajor = 0, 
		g_shOSVersionMinor = 0;
bool		g_bSixthFailed = false;


//////////////////////////////////////////////////////////////////////////////

bool	    FirstStage( );
bool		SecondStage();
bool		ThirdStage( bool bDirectNTQSI = false);
bool		FourthStage( bool bDirectNTQSI = false);		// Fourth and Fifth stage
bool		SixthStage( unsigned short usSessID, bool bDirectNTQSI = false);
bool		SeventhStage( bool bDirectNTQSI = false);
bool		EighthStage();

bool		IsCSRSSProcess( DWORD dwPID);

int		SearchInTable( DWORD *aPIDs, DWORD dwTarget );
void		SortArray(DWORD* aTab, DWORD n);
bool		SimpleArrayCompare( DWORD *aTab1, DWORD *aTab2, DWORD dwN);
void		DifferenceTables( DWORD dwNum1, DWORD dwNum2);
void		DumpTables();

int		APIHookCheck();
void		ShowNotMatchedProcesses();

BOOL		SetPrivilege( HANDLE hToken, LPCSTR lpPrivName, BOOL bEnable );

NTSTATUS __stdcall direct_NtQuerySystemInformation( ULONG  SystemInformationClass, 
						   PVOID  SystemInformation, 
						   ULONG  SystemInformationLength,
						   PULONG ReturnLength );


//////////////////////////////////////////////////////////////////////////////

int _tmain(int argc, _TCHAR* argv[])
{
	// Getting OS version.
	OSVERSIONINFOA	osVerInfo;
	memset( &osVerInfo, 0, sizeof osVerInfo);
	osVerInfo.dwOSVersionInfoSize = sizeof osVerInfo;
	GetVersionExA( &osVerInfo);
	
	g_shOSVersionMajor = osVerInfo.dwMajorVersion;
	g_shOSVersionMinor = osVerInfo.dwMinorVersion;

	memset( g_dwPIDs, 0xFFFFFFFF, NUMBER_OF_STAGES * MAX_PROCESSES * sizeof DWORD);
	memset( g_dwNumOfProcs, 0, NUMBER_OF_STAGES * sizeof DWORD);

	printf(	"\n\tProcess-list cross-checking and native API hook testing security tool.\nPRC_XCHK v0.2"
		"\tOSVer:  %d.%d.%d\tMGeeky's bench '09, mgeeky@gmail.com\n", 
		osVerInfo.dwMajorVersion, osVerInfo.dwMinorVersion, osVerInfo.dwBuildNumber );
	puts(	"\nHidden processes scanner with simple/naive native API hooks tester.\n\n");

	HANDLE hToken;			
	OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if( !SetPrivilege( hToken, "SeDebugPrivilege", TRUE) 
	 || !SetPrivilege(hToken, "SeBackupPrivilege", TRUE))
		printf( "[!] Cannot set required privileges to current process, err: %d", GetLastError() );

	pNtQuerySystemInformation = (NTQSI)GetProcAddress(	GetModuleHandleA( "NTDLL.DLL"), 
								"NtQuerySystemInformation");
	_RtlNtStatusToDosError	= (RNSTDE) GetProcAddress( GetModuleHandleA( "NTDLL.DLL"), 
								"RtlNtStatusToDosError" );
	if( pNtQuerySystemInformation == NULL)
	{
		printf( "[!] Failed while obtaining NtQuerySystemInformation proc address !\n");
		return 1;
	}
	
	// Perfroming several scans...
	{
		g_dwPIDs[ 3][0] = g_dwPIDs[ 7][0] = g_dwPIDs[ 9][0] = g_dwPIDs[ 4][0] = 0;
		g_dwPIDs[ 4][1] = 4;
		g_dwNumOfProcs[ 3] = g_dwNumOfProcs[ 7] = g_dwNumOfProcs[ 9] = 1;
		g_dwNumOfProcs[ 4] = 2;

		FirstStage();
		SecondStage();

		ThirdStage();
		FourthStage();

		for( int i = 0; i < 2; i++)
			SixthStage( i);
		SeventhStage();

		EighthStage();

		puts( "\n\t****   Alternative method scan - using direct system call  ****\n");
		ThirdStage( true );
		FourthStage(true );
		for( int i = 0; i < 2; i++)
			SixthStage( i, true);
		SeventhStage( true );
	}

	puts( "\n\n\t\t*********************************************\n");

	// Sanity checks

	puts( "Ordinary sanity checks...");

#define CHK( x ) _CHK1( a ## x, x)
#define STICK( x) a ## x
#define _CHK1( x, y) unsigned x;for(x=0;;x++){if(g_dwPIDs[y][x]==0xFFFFFFFF)break;}

	for( unsigned u = 0; u < NUMBER_OF_STAGES; u++)
	{
		if( g_bSixthFailed && u == 5 || u == 10) continue;

		CHK( u)
		if( g_dwNumOfProcs[ u] != STICK( u) ) 
			printf( "\t[!] Number of elements (%d) in %d array are not match with counter (%d) !\n",
				STICK( u), u, g_dwNumOfProcs[ u] );
		g_dwNumOfProcs[ u] = STICK( u);
	}

	for( unsigned u = 0; u < NUMBER_OF_STAGES; u++)
		SortArray( g_dwPIDs[ u], g_dwNumOfProcs[ u]);

	printf( "\nAnalysing results...\nChecking for any native API Hooks...");

	int iRet = APIHookCheck();
	if( !iRet)			printf( "\t\tSystem seems to be CLEAR.\n\n\t\t"
						"YOURS OPERATING SYSTEM IS (seems to be) HEALTHY !");
	else{
		printf( "\t\t\tProbability of ROOTKIT infection !");

		switch( iRet)
		{
			case 1:
				printf( "\n\t[!] Found hook on NtQuerySystemInformation( SystemProcessInformation, ...);");
				DifferenceTables( 2, 8 );
				break;
			case 2:
				printf( "\n\t[!] Found hook on NtQuerySystemInformation( SystemHandleInformation, ...);");
				DifferenceTables( 3, 9 );
				break;
			case 3:
				printf( "\n\t[!] Found hook on NtQuerySystemInformation( "
						"SystemSessionProcessInformation, ...);");
				DifferenceTables( 5, 10 );
				break;
			case 4:
				printf( "\n\t[!] Found hook on NtQuerySystemInformation( "
						"SystemExtendedProcessInformation, ...);");
				DifferenceTables( 6, 11 );
				break;
			default:
				printf( "\n\t[!] Threat found at APIHookCheck test: %d", iRet);
				break;
		}

		puts("\n\t\t\t! ***  Suspicious processes list  *** !");
		ShowNotMatchedProcesses();
	}
	getchar();
	return 0;
}


//////////////////////////////////////////////////////////////////////////////

int SearchInTable( DWORD *aPIDs, DWORD dwTarget )
{
	for( unsigned u = 0; u < MAX_PROCESSES; u++)
		if( aPIDs[ u] == dwTarget ) return u;
		else continue;
	return -1;
}


//////////////////////////////////////////////////////////////////////////////
// Ascending table sort method

void _SortArray(DWORD* aTab, DWORD n)
{
	n--;
	if( n <= 0 || n > MAX_PROCESSES ) return;

	DWORD	dwCounter = 0, 
			dwTemp = 0;
	do{
		dwCounter = 0;
		for(DWORD i = 0; i < n-1; i++)
			if(aTab[i] > aTab[i+1])
			{
				dwTemp		= aTab[i];
				aTab[i]		= aTab[i+1];
				aTab[i+1]	= dwTemp;
				dwCounter++;
			}
	}while( dwCounter);
}


void SortArray(DWORD* aTab, DWORD n)
{
	_SortArray( aTab, n);
	_SortArray( aTab, n);
	_SortArray( aTab, n);
}


//////////////////////////////////////////////////////////////////////////////
inline bool SimpleArrayCompare( DWORD *aTab1, DWORD *aTab2, DWORD dwN)
{
	for( unsigned u = 0; u < dwN; u++)
		if( aTab1[u] != aTab2[u]) return false;
	return true;
}


//////////////////////////////////////////////////////////////////////////////

bool IsCSRSSProcess( DWORD dwPID)
{
#if	_WIN32_WINNT < _WIN32_WINNT_LONGHORN
	if( dwPID == g_dwCSRSS_PID) return true;
	else return false;
#else
	for( unsigned u = 0; u < (sizeof( g_dwCSRSS_PID) / sizeof DWORD); u++)
		if( g_dwCSRSS_PID[ u] == dwPID) return true;
	return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
// Function prototype copied from: 
//		http://www.rootkitanalytics.com/userland/Hidden-Process-Detection.php

__declspec(naked)
NTSTATUS __stdcall direct_NtQuerySystemInformation( ULONG  SystemInformationClass, 
						    PVOID  SystemInformation, 
						    ULONG  SystemInformationLength,
						    PULONG ReturnLength )	
{
	//For Windows 2000
	if( g_shOSVersionMajor == 5 && g_shOSVersionMinor == 0 )
	{
		__asm
		{
			mov eax, 0x97
			lea edx, DWORD PTR ss:[esp+4]
			INT 0x2E
			ret 0x10
		}	
	}	

	//For Windows XP
	if( g_shOSVersionMajor == 5 && g_shOSVersionMinor == 1 )
	{
		__asm
		{
			mov eax, 0xAD     
			call SystemCall_XP
			ret 0x10
			
		SystemCall_XP:
			mov edx, esp
			_emit 0x0F		// sysenter - C2400 error bypass method
			_emit 0x34
		}	
	}									
									
	//For Windows Vista & Longhorn
	if( g_shOSVersionMajor == 6 && g_shOSVersionMinor == 0 )
	{
		__asm
		{
			mov eax, 0xF8    
			call SystemCall_VISTA
			ret 0x10
			
		SystemCall_VISTA:
			mov edx, esp
			_emit 0x0F		// sysenter - C2400 error bypass method
			_emit 0x34
		}	
	}

										
	//For Windows 7
	if( g_shOSVersionMajor == 6 && g_shOSVersionMinor == 1 )
	{
		__asm
		{
			mov eax, 0x105
			call SystemCall_7
			ret 0x10
			
		SystemCall_7:
			mov edx, esp
			_emit 0x0F		// sysenter - C2400 error bypass method
			_emit 0x34
		}	
	}

	__asm{ ret 0x10}
}


///////////////////////////////////////////////////////////////

BOOL SetPrivilege( HANDLE hToken, LPCSTR lpPrivName, BOOL bEnable )
{
	TOKEN_PRIVILEGES	tpPrivileges;
	LUID				lLocalUniqueID;

	/* Look for unique ID of choosen privilege type */
	if( ! LookupPrivilegeValueA( NULL /* Local system */, lpPrivName, 
								&lLocalUniqueID ) ){
		/* Cannot look for privilege value by its name */
		return FALSE;
	}else{
		/* Filling TOKEN_PRIVILEGE structure */
		tpPrivileges.PrivilegeCount = 1;			/* Sets number of privilege to modify */
		tpPrivileges.Privileges[0].Luid = lLocalUniqueID;	/* Sets local unique ID of  privilege */

		tpPrivileges.Privileges[0].Attributes = (bEnable )? SE_PRIVILEGE_ENABLED    /* Enable		*/
				    				: SE_PRIVILEGE_REMOVED;	    /* or Disable	*/
		/* Adjusting privileges of access token */				    /* privilege	*/
		if( ! AdjustTokenPrivileges( hToken, FALSE, &tpPrivileges, sizeof( tpPrivileges),
									 (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL ) )
		{
			/* Cannot change privileges of this typed access token */
			return FALSE;
		}
	}
	return TRUE;
}


//////////////////////////////////////////////////////////////////////////////
// First stage procedure. That proc is checking working process list returned from
// CreateToolhelp32Snapshot function, and than iterates on PROCESSENTRY32 stucture.

bool FirstStage()
{
	HANDLE			hSnapshot;
	PROCESSENTRY32W	*pePrcList;
	unsigned		uPrcCounter = g_dwNumOfProcs[ 0];
#if _WIN32_WINNT >= _WIN32_WINNT_LONGHORN
	unsigned		uCSRSSCounter = 0;
#endif

	pePrcList = (PROCESSENTRY32W*)malloc( sizeof( PROCESSENTRY32W));
	if( pePrcList == NULL)
	{
		printf( "\t[!] malloc failed. Possible heap corruption: %d\n", GetLastError() );
		return false;
	}

	memset( pePrcList, 0, sizeof(pePrcList) );
	pePrcList->dwSize = sizeof(PROCESSENTRY32W);

	// ------------------

	printf( "[1] ToolHlp stage...");
	
	hSnapshot = CreateToolhelp32Snapshot( 2 /* TH32CS_SNAPPROCESS */, 0);
	if( hSnapshot == (HANDLE)-1)
	{
		printf( "\t\t\t[!] Toolhelp snapshot failed: %d\n", GetLastError() );
		free( (void*)pePrcList);
		return false;
	}
	
	if( !Process32FirstW( hSnapshot, pePrcList) || GetLastError() == ERROR_NO_MORE_FILES )
	{
		printf( "\t\t\t\t[!] Process32First failed: %d\n", GetLastError() );
		free( (void*)pePrcList);
		return false;
	}

	while( true)
	{
		g_dwPIDs[ 0][ uPrcCounter++] = pePrcList->th32ProcessID;

#if _WIN32_WINNT < _WIN32_WINNT_LONGHORN
		if( 0 != wcsstr(pePrcList.szExeFile, L"csrss.exe") )
			g_dwCSRSS_PID = pePrcList.th32ProcessID;
#else
		if( 0 != wcsstr(pePrcList->szExeFile, L"csrss.exe") )
			g_dwCSRSS_PID[ uCSRSSCounter++] = pePrcList->th32ProcessID;
#endif

		if( !Process32NextW( hSnapshot, pePrcList)) break;
	}

	printf( "\t\t\t\t\tResult: %d PIDs found.\n", uPrcCounter);
	g_dwNumOfProcs[ 0] = uPrcCounter;

	free( (void*)pePrcList);
	return true;
}



//////////////////////////////////////////////////////////////////////////////
// Second stage procedure. This procedure enumerates working processes by using
// PSAPI functions. 

bool SecondStage()
{
	DWORD		dwBytesReturned = 0;
	unsigned	uPrcCounter = g_dwNumOfProcs[ 1];
	
	printf( "[2] PSAPI stage...");

	if( !EnumProcesses( g_dwPIDs[ 1], MAX_PROCESSES * sizeof DWORD, &dwBytesReturned ))
	{
		printf( "[!] EnumProcesses failed: %d !\n", GetLastError());
		return false;
	}

	uPrcCounter = unsigned( dwBytesReturned / sizeof DWORD );

	printf( "\t\t\t\t\tResult: %d PIDs found.\n", uPrcCounter);
	g_dwNumOfProcs[ 1] = uPrcCounter;

	return true;
}


//////////////////////////////////////////////////////////////////////////////
// Third stage - NtQuerySystemInformation #1 - gathering process list by
// first question to above proc.

bool ThirdStage( bool bDirectNTQSI)
{
	short	sIndex = (bDirectNTQSI)? 2 : 8;
	DWORD	dwPrcCounter = g_dwNumOfProcs[ sIndex], dwTmp = 0;
	ULONG	ulReceivedBytes = 0;
	
	NTQSI	_pNTQSI = pNtQuerySystemInformation;
	if( bDirectNTQSI) _pNTQSI = (NTQSI)direct_NtQuerySystemInformation;
	
	SYSTEM_PROCESS_INFORMATION2	*spiProcesses = NULL;

	if( !bDirectNTQSI)printf( "[3] NtQuerySystemInformation #1...");
	else printf( "[9]  NtQuerySystemInformation #1 (syscall)...");


	NTSTATUS ntRet = _pNTQSI(	5 /* SystemProcessInformation */, spiProcesses, 
					0, &ulReceivedBytes );
	if( !NT_SUCCESS( ntRet) ) 
	{
		// Not allocated much space

		dwTmp = ulReceivedBytes+1;
		DWORD dwTmp2 = 0;
		ulReceivedBytes = 0;
		spiProcesses = (SYSTEM_PROCESS_INFORMATION2*)VirtualAlloc( 0, dwTmp, MEM_COMMIT, PAGE_READWRITE);
		if( spiProcesses == NULL)
		{
			printf( "\n\t[!] VirtualAlloc failed: %d (size: %d)", GetLastError(), dwTmp);
			return false;
		}

		memset( (void*)spiProcesses, 0, dwTmp);
		if( (dwTmp2 = _pNTQSI( 5 /* SystemProcessInformation */, (PVOID)spiProcesses, 
								dwTmp, &ulReceivedBytes )) != 0)
		{
			if( GetLastError() == 87)
			{
				printf( "\t\t\tNEEDED RESTART OF THIS STAGE\n");
			}else printf( "\n\t[!] NtQuerySystemInformation failed: %d (NTSTATUS: %X/%d)\n", 
					GetLastError(), dwTmp2, _RtlNtStatusToDosError(dwTmp2));
			VirtualFree( (LPVOID)spiProcesses, dwTmp, MEM_DECOMMIT);
			return false;
		}
	}

	while( 1)
	{
		if( spiProcesses == NULL) break;
		if( spiProcesses->NextEntryOffset == 0) break;

		g_dwPIDs[ sIndex][ dwPrcCounter] = (DWORD)spiProcesses->ProcessId;
		spiProcesses = (SYSTEM_PROCESS_INFORMATION2*)( DWORD(spiProcesses) + 
							spiProcesses->NextEntryOffset );

		wprintf( L"\rNtQuerySystemInformation #1...\tfound:\tpid: %.4d, \"%s\"\r", 
				spiProcesses->ProcessId, spiProcesses->ImageName.Buffer);
		fflush( stdout);

		dwPrcCounter++;
		Sleep( 10);
	}

	VirtualFree( (LPVOID)spiProcesses, dwTmp, MEM_DECOMMIT);

	if( !bDirectNTQSI)
		printf( "[3] NtQuerySystemInformation #1...\t\t\tResult: %d PIDs found.\n", dwPrcCounter);
	else 
		printf( "[9] NtQuerySystemInformation #1 (syscall)...\t\tResult: %d PIDs found.\n", dwPrcCounter);

	g_dwNumOfProcs[ sIndex] = dwPrcCounter;
	return true;
}


//////////////////////////////////////////////////////////////////////////////
// Fourth stage - NtQuerySystemInformation #2 - gathering PIDs list by
// second question to above proc. Now, we will use global HANDLE list

bool FourthStage( bool bDirectNTQSI )
{
	short				sIndex		= (bDirectNTQSI)? 3 : 9;
	DWORD				dwSize		= 0, dwTmp = 0, dwTmp2;
	SYSTEM_HANDLE_INFORMATION	*shiHandles	= (SYSTEM_HANDLE_INFORMATION*)malloc( 0x100);
	HANDLE				hCSRSS		= (HANDLE)-1, hTmp = (HANDLE)-1;
	unsigned			uPrcCounter1= g_dwNumOfProcs[ sIndex], 
					uPrcCounter2= g_dwNumOfProcs[ 4] ;
		
	NTQSI	_pNTQSI = pNtQuerySystemInformation;
	if( bDirectNTQSI) _pNTQSI = (NTQSI)direct_NtQuerySystemInformation;

	if( !bDirectNTQSI)printf( "[4] NtQuerySystemInformation #2...");
	else printf( "[10] NtQuerySystemInformation #2 (syscall)...");

	if( _pNTQSI(	16 /* SystemHandleInformation */, (PVOID)shiHandles, 
			0x100, &dwSize ) != 0)
	{
		// Not allocated much space
		free( (void*)shiHandles);

		dwTmp = dwSize;
		dwSize = 0;
		shiHandles = (SYSTEM_HANDLE_INFORMATION*)malloc( dwTmp);
		memset( (void*)shiHandles, 0, dwTmp);

		if( (dwTmp2 = _pNTQSI( 16 /* SystemHandleInformation */, (PVOID)shiHandles, 
					dwTmp, &dwSize )) != 0)
		{
			if( GetLastError() == 87)
			{
				printf( "\t\tNEEDED RESTART OF THIS STAGE\n");
			}else printf( "\n\t[!] NtQuerySystemInformation failed: %d (NTSTATUS: %X/%d)\n", 
						GetLastError(), dwTmp2, _RtlNtStatusToDosError(dwTmp2));
			free( (void*)shiHandles);

			if( !bDirectNTQSI)printf( "\t[?] Stage 5th skipped because of error in stage 4th.\n");
			return false;
		}
	}

	for( unsigned u = 0; u < shiHandles->HandleCount; u++)
	{
		if( SearchInTable( g_dwPIDs[ sIndex], shiHandles->Handles[u].OwnerPid) == -1 )
			uPrcCounter1 ++;

		if( uPrcCounter1 > 0 ) 
			g_dwPIDs[ sIndex][ uPrcCounter1-1] = shiHandles->Handles[u].OwnerPid;

		// Fifth stage. Looking for CSRSS process handles
		if( shiHandles->Handles[u].ObjectType == HANDLE_TYPE_PROCESS
			&& IsCSRSSProcess(shiHandles->Handles[u].OwnerPid) )
		{			
			hCSRSS = OpenProcess( PROCESS_DUP_HANDLE, false, shiHandles->Handles[u].OwnerPid );
			if( hCSRSS )
			{
				if( DuplicateHandle(	hCSRSS, (HANDLE)shiHandles->Handles[u].HandleValue, 
										GetCurrentProcess(), &hTmp, 
										PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, 0) )
					if( SearchInTable( g_dwPIDs[ 4], GetProcessId(hTmp)) == -1 )
						g_dwPIDs[ 4][ uPrcCounter2++] = GetProcessId(hTmp);

				CloseHandle( hCSRSS);
				CloseHandle( hTmp);
			}
			else
			{
				static bool bOnce = false;
				if( bOnce == true) continue;

				printf( "\t[!] Cannot open CSRSS process! PID: %d, Err: %d\n", 
					shiHandles->Handles[u].OwnerPid, GetLastError() );
				bOnce = true;
			}
		}
	}
	free( (void*)shiHandles);
	
	if( !bDirectNTQSI) printf( "\t");
	printf( "\t\tResult: %d PIDs found.\n", uPrcCounter1);
	g_dwNumOfProcs[ sIndex] = uPrcCounter1;

	if( !bDirectNTQSI){
		printf( "[5] Searching inside CSRSS PIDs/handles base...");
		printf( "\t\tResult: %d/%d PIDs found\n", uPrcCounter2, uPrcCounter1);
		g_dwNumOfProcs[ 4] = uPrcCounter2;
	}

	return true;
}

//////////////////////////////////////////////////////////////////////////////
// Sixth stage - NtQuerySystemInformation #3 - gathering process list by
// first question to above proc. Now, we will use SystemSessionProcessInformation class
// that is nearly exactly same that SystemProcessInformation is.

bool SixthStage( unsigned short usSessID, bool bDirectNTQSI)
{
	static bool bFailed = false;
	if( bFailed == true) return true;

	short	sIndex		= (bDirectNTQSI)? 5 : 10;
	DWORD	dwPrcCounter	= g_dwNumOfProcs[ sIndex], dwTmp = 0;
	ULONG	ulReceivedBytes = 0;

	NTQSI	_pNTQSI = pNtQuerySystemInformation;
	if( bDirectNTQSI) _pNTQSI = (NTQSI)direct_NtQuerySystemInformation;
	
	PVOID	pBuffer		= malloc( 0x100);

	SYSTEM_SESSION_PROCESS_INFORMATION	sspiInfo;
	sspiInfo.SessionId	= usSessID;
	sspiInfo.BufferLength	= 0x100;
	sspiInfo.Buffer		= pBuffer;

	if(!bDirectNTQSI) printf( "[6] NtQuerySystemInformation #3...");
	else printf( "[11] NtQuerySystemInformation #3 (syscall)...");

	NTSTATUS ntRet = _pNTQSI(	53 /* SystemSessionProcessInformation */, 
					&sspiInfo, 0x100, &ulReceivedBytes );
	if( !NT_SUCCESS( ntRet) ) 
	{
		// Not allocated much space

		sspiInfo.SessionId	= usSessID;
		sspiInfo.BufferLength	= ulReceivedBytes+1;
		sspiInfo.Buffer		= pBuffer;

		free( (void*)pBuffer);

		DWORD dwTmp = ulReceivedBytes+1, dwTmp2 = 0;
		ulReceivedBytes = 0;
		pBuffer = malloc( dwTmp);
		memset( (void*)pBuffer, 0, dwTmp);

		if( (dwTmp2 = _pNTQSI( 53 /* SystemSessionProcessInformation */, 
					 (PVOID)&sspiInfo, dwTmp, &ulReceivedBytes )) != 0)
		{
			bFailed = true;

			if( _RtlNtStatusToDosError(dwTmp2) == 998)
				printf( "\t\t\t[!] Memory access error\n");
			else if( GetLastError() == 5) printf( "\t\t\tAccess Denied !\n"); 
			else printf( "\n\t[!] NtQuerySystemInformation failed: %d (NTSTATUS: %X/%d)\n", 
						GetLastError(), dwTmp2, _RtlNtStatusToDosError(dwTmp2));

			free( (void*)pBuffer);

			g_bSixthFailed = true;
			return false;
		}
	}

	SYSTEM_PROCESS_INFORMATION2	*spiProcesses = (PSYSTEM_PROCESS_INFORMATION2)sspiInfo.Buffer;

	for( unsigned u = 0;; u++)
	{
		if( spiProcesses[ u].NextEntryOffset == 0) break;
		g_dwPIDs[ sIndex][ dwPrcCounter] = (DWORD)spiProcesses[ u].ProcessId;

		dwPrcCounter++;
	}

	free( (void*)pBuffer);

	printf( "\t\t\tResult: %d PIDs found.\n", dwPrcCounter);

	g_dwNumOfProcs[ sIndex] = dwPrcCounter;

	return true;
}


//////////////////////////////////////////////////////////////////////////////
// Seventh stage - NtQuerySystemInformation #3 - gathering process list by
// first question to above proc. Now, we will use SystemExtendedProcessInformation (57)
// class 

bool SeventhStage( bool bDirectNTQSI)
{
	SYSTEM_EXTENDED_PROCESS_INFORMATION	*spiProcInfo = 
				    		(SYSTEM_EXTENDED_PROCESS_INFORMATION*)malloc( 0x100);
	unsigned		sIndex = (bDirectNTQSI)? 6 : 11;
	DWORD			dwTmp = 0, dwTmp2 = 0x100, nRet = 0, 
				dwPrcCounter = g_dwNumOfProcs[ sIndex];
		
	NTQSI	_pNTQSI = pNtQuerySystemInformation;
	if( bDirectNTQSI) _pNTQSI = (NTQSI)direct_NtQuerySystemInformation;

	if( !bDirectNTQSI) printf( "[7] NtQuerySystemInformation #4...");
	else printf( "[11] NtQuerySystemInformation #4 (syscall)...");

	if( _pNTQSI( 57 /* SystemExtendedProcessInformation */, (PVOID)spiProcInfo,
		    dwTmp2, &dwTmp) != 0)
	{
		free( (void*)spiProcInfo );
		dwTmp++;
		dwTmp2 = 0;

		spiProcInfo = (SYSTEM_EXTENDED_PROCESS_INFORMATION*)
					VirtualAlloc( 0, dwTmp, MEM_COMMIT, PAGE_READWRITE);
		if( spiProcInfo == NULL)
		{
			printf( "\n\t[!] VirtualAlloc failed: %d (size: %d)", GetLastError(), dwTmp);
			return false;
		}
		memset( (void*)spiProcInfo, 0, dwTmp);

		if( (nRet = _pNTQSI( 57 /* SystemExtendedProcessInformation */,
					(PVOID)spiProcInfo, dwTmp, &dwTmp2 )) != 0)
		{
			if( GetLastError() != 5)
				printf( "\n\t[!] NtQuerySystemInformation failed: %d (NTSTATUS: %X/%d)\n", 
					GetLastError(), dwTmp2, _RtlNtStatusToDosError(dwTmp2));
			else printf( "\t\t\tAccess Denied !\n"); 

			VirtualFree( (LPVOID)spiProcInfo, dwTmp, MEM_DECOMMIT);
			return false;
		}
	}

	for( unsigned u = 0; ; u++)
	{
		if( spiProcInfo->NextEntryOffset == 0) break;

		g_dwPIDs[ sIndex][ dwPrcCounter++] = (DWORD)spiProcInfo->UniqueProcessId;

		spiProcInfo = (SYSTEM_EXTENDED_PROCESS_INFORMATION*)
					( DWORD(spiProcInfo) + spiProcInfo->NextEntryOffset);
	}

	VirtualFree( (LPVOID)spiProcInfo, dwTmp, MEM_DECOMMIT);

	if( !bDirectNTQSI) printf( "\t");
	printf( "\t\tResult: %d PIDs found.\n", dwPrcCounter);
	g_dwNumOfProcs[ sIndex] = dwPrcCounter;

	return true;
}


//////////////////////////////////////////////////////////////////////////////
// Eighth stage - brute force working process scan method.

bool EighthStage()
{
	DWORD		dwPID = 0;
	HANDLE		hProcess;
	unsigned	uPrcCounter = g_dwNumOfProcs[ 7];

	printf( "[8] Brute-force scanning method...\r");

	for(unsigned u = 0; u < 0x83B8; u += 4)
	{
		printf( "[8] Brute-force scanning method...\tScanning possible PID: %d ( %Xh )\r", u, u);

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, u);
		if( hProcess == NULL  )
		{
	
			if( GetLastError() != ERROR_INVALID_PARAMETER)
			{
				// Process is protected against ordinary opening process
				g_dwPIDs[ 7][ uPrcCounter] = (DWORD)u;
				uPrcCounter++;
				continue;
			}
		}

		DWORD dwExitCode = 0;
		GetExitCodeProcess(hProcess, &dwExitCode);

		// check if this is active process...
		// only active process will return error 
		// code as ERROR_NO_MORE_ITEMS

		if( dwExitCode == ERROR_NO_MORE_ITEMS ){  
			g_dwPIDs[ 7][ uPrcCounter] = (DWORD)u;
			uPrcCounter++;
		}

		CloseHandle(hProcess);
	}

	printf( "[8] Brute-force scanning method...\t\t\tResult: %d PIDs found.\n", uPrcCounter);

	g_dwNumOfProcs[ 7] = uPrcCounter;

	return true;
}

//////////////////////////////////////////////////////////////////////////////
#define COMP( x, y, z)	if( !SimpleArrayCompare( g_dwPIDs[ x], g_dwPIDs[ y], \
							g_dwNumOfProcs[ x]) ) return z;
int APIHookCheck()
{
	COMP( 2, 8, 1);
	COMP( 3, 9, 2);
	if( !g_bSixthFailed) COMP( 5, 10,3);
	COMP( 6, 11,4);
	

	return 0;
}


//////////////////////////////////////////////////////////////////////////////

void PrintBasicProcessInfo( DWORD dwPID)
{
	if( dwPID == 0 || dwPID == 4) return;

	char *szImagePath = (char*)malloc( 512);
	memset( szImagePath, 0, 512);

	strcpy_s( szImagePath, 511, "(N/A)");

	//HANDLE hProcess = 
	//GetModuleFileNameExA( hProcess, NULL, szImagePath, 511);

	static int iCounter = 0;
	printf( "[%d] %d (%X) - \"%s\" \n", iCounter++, dwPID, dwPID, szImagePath );

	free( szImagePath);
}


//////////////////////////////////////////////////////////////////////////////

#define SEARCH( x, y)	for( unsigned u = 0; u < g_dwNumOfProcs[ x]; u++) \
				if( -1 == SearchInTable( g_dwPIDs[ y], g_dwPIDs[ x][ u]) )\
				    PrintBasicProcessInfo( g_dwPIDs[ x][ u]);

void ShowNotMatchedProcesses()
{
	puts("");

	for( unsigned u = 0; u < g_dwNumOfProcs[ 8]; u++)
	{
		if( u == 0 || u == 4) continue;
		if( -1 == SearchInTable( g_dwPIDs[2], g_dwPIDs[ 8][ u]) )
			PrintBasicProcessInfo( g_dwPIDs[ 8][ u]);
	}

	for( unsigned u = 0; u < g_dwNumOfProcs[ 9]; u++)
	{
		if( u == 0 || u == 4) continue;
		if( -1 == SearchInTable( g_dwPIDs[3], g_dwPIDs[ 9][ u]) )
			PrintBasicProcessInfo( g_dwPIDs[ 9][ u]);
	}

	if( !g_bSixthFailed)
		for( unsigned u = 0; u < g_dwNumOfProcs[ 10]; u++)
		{
			if( u == 0 || u == 4) continue;
			if( -1 == SearchInTable( g_dwPIDs[5], g_dwPIDs[ 10][ u]) )
				PrintBasicProcessInfo( g_dwPIDs[ 10][ u]);
		}

	for( unsigned u = 0; u < g_dwNumOfProcs[ 11]; u++)
	{
		if( u == 0 || u == 4) continue;
		if( -1 == SearchInTable( g_dwPIDs[6], g_dwPIDs[ 11][ u]) )
			PrintBasicProcessInfo( g_dwPIDs[ 11][ u]);
	}

	SEARCH( 8, 2)
	SEARCH( 9, 3)
	SEARCH( 10,5)
	SEARCH( 11,6)
	
}


//////////////////////////////////////////////////////////////////////////////

void DifferenceTables( DWORD dwNum1, DWORD dwNum2)
{
	puts("");

	DWORD	dwMin = ( g_dwNumOfProcs[ dwNum1] > g_dwNumOfProcs[ dwNum2] )? g_dwNumOfProcs[ dwNum1] :
					    				   g_dwNumOfProcs[ dwNum2] ;
	DWORD	dwSubstract = 0;
	if( g_dwNumOfProcs[ dwNum1] > dwMin)	    dwSubstract = g_dwNumOfProcs[ dwNum1] - dwMin;
	else if( g_dwNumOfProcs[ dwNum2] > dwMin)   dwSubstract = g_dwNumOfProcs[ dwNum2] - dwMin;

	for( unsigned u = 0; u < dwMin; u++)
	{
		if( u % 3 == 0 ) puts( "");
		printf( "%d. %X - %X\t", u, g_dwPIDs[ dwNum1], g_dwPIDs[ dwNum2] );
	}

	for( unsigned u = 0; u < dwSubstract; u++)
	{
		if( u % 3 == 0 ) puts( "");
		printf( "%d. %X - ??\t", u, (g_dwNumOfProcs[ dwNum1]==dwMin)? 
						g_dwPIDs[ dwNum1] : g_dwPIDs[ dwNum2] );
	}
}


//////////////////////////////////////////////////////////////////////////////

void DumpTables()
{
	printf( "==\t0\t1\t2\t3\t4\t6\t7\t8\t9\t11\n");
	for( unsigned u = 0; u < g_dwNumOfProcs[ 0]; u++)
	{
		printf( "%d.\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", u, 
			g_dwPIDs[ 0][u], g_dwPIDs[ 1][u], g_dwPIDs[ 2][u], g_dwPIDs[ 3][u],
			g_dwPIDs[ 4][u], g_dwPIDs[ 6][u], g_dwPIDs[ 7][u], g_dwPIDs[ 8][u], 
			g_dwPIDs[ 9][u], g_dwPIDs[ 11][u]);
	}
}
