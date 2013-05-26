/******************************************************************************
Name:
bkdump.exe

Version:
0.3
*  0.2 added the ability to scan other processes and pids
*  0.3 added code and layout updates recommended by 0xdabbad00

Description:
Starts iexplore.exe and then dumps any memory that has RWX rights. POC only tested on Win XP. 

Author:
alexander<dot>hanel<at>gmail<dot>com

License:
bkdump is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see
<http://www.gnu.org/licenses/>.

Notes:
* Best technique for finding dynamically loaded dlls in a process space?

To Do:

Useful Links:
http://www.youtube.com/watch?NR=1&v=lwFIC7It3Fc&feature=endscreen  <- most of the code came from here. Awesome Video!
http://www.catch22.net/tuts/undocumented-createprocess
http://www.blizzhackers.cc/viewtopic.php?p=2483118
http://cboard.cprogramming.com/windows-programming/102965-help-mbi-baseaddress-loop.html

******************************************************************************/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <tchar.h>

typedef struct _MEMBLOCK
{
	HANDLE hProc;
	unsigned char *addr;
	int size;
	unsigned char *buffer;
	struct _MEMBLOCK *next;

} MEMBLOCK;

typedef struct _PSLIST
{
	int pid;
	TCHAR psname[MAX_PATH];
	struct _PSLIST *next;

} PSLIST;

/******************************************************************************
* This function gets the PID and Process Path for a set of process names
******************************************************************************/
PSLIST* GetProcessList( )
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	int i;
	int psNameSize = 0;
	TCHAR psName[][20] = { "firefox.exe", "iexplore.exe", "chrome.exe", "explorer.exe"};
	PSLIST* head, *curr; 
	head = NULL; 
	
	psNameSize = sizeof(psName)/sizeof(psName[0]);
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		printf("CreateToolhelp32Snapshot (of processes)");
		return( NULL );
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if( !Process32First( hProcessSnap, &pe32 ) )
	{
		printf("Process32First Failed"); // show cause of failure
		CloseHandle( hProcessSnap );          // clean the snapshot object
		return( NULL );
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		// loop through the process name list 
		for ( i = 0; i < psNameSize ; i++)
		{
			if( _stricmp(psName[i], pe32.szExeFile ) == 0)
			{
				curr = (PSLIST *) malloc ( sizeof ( PSLIST ) );
				curr->pid = pe32.th32ProcessID;
				strcpy( curr->psname, pe32.szExeFile );
				curr->next  = head;
				head = curr;
			}
		}

	} while( Process32Next( hProcessSnap, &pe32 ) );
	curr = head;

	CloseHandle( hProcessSnap );
	return( curr );
}

/******************************************************************************
* This function adjusts the process token.  
******************************************************************************/
BOOL EnableTokenPrivilege (LPTSTR pPrivilege)
{
	// Source http://cboard.cprogramming.com/c-programming/108648-help-readprocessmemory-function.html#post802074
	HANDLE hToken;                        
	TOKEN_PRIVILEGES token_privileges;                  
	DWORD dwSize;                        
	ZeroMemory (&token_privileges, sizeof (token_privileges));
	token_privileges.PrivilegeCount = 1;
	if ( !OpenProcessToken (GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		printf("OpenProcessToken failed");
		return FALSE;
	}
	if (!LookupPrivilegeValue ( NULL, pPrivilege, &token_privileges.Privileges[0].Luid))
	{ 
		printf("LookupPrivilegeValue failed");
		CloseHandle (hToken);
		return FALSE;
	}
	token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges ( hToken, FALSE, &token_privileges, 0, NULL, &dwSize))
	{ 
		printf("AdjustTokenPrivileges failed");
		CloseHandle (hToken);
		return FALSE;
	}
	CloseHandle (hToken);
	return TRUE;
}

/******************************************************************************
* This function creates a memory block struct 
******************************************************************************/
MEMBLOCK* create_memblock (HANDLE hProc,  MEMORY_BASIC_INFORMATION *meminfo)
{
	// used to create the membloc
	MEMBLOCK *mb = malloc(sizeof(MEMBLOCK));

	if (mb)
	{
		mb->hProc = hProc;
		mb->addr = meminfo->BaseAddress;
		mb->size = meminfo->RegionSize;
		mb->buffer = malloc(meminfo->RegionSize);
		mb->next = NULL;

	}
	return mb;
}

/******************************************************************************
* This function creates a free memory block struct 
******************************************************************************/
void free_memblock (MEMBLOCK *mb)
{
	if (mb)
	{
		if (mb->buffer)
		{
			free (mb->buffer);
		}
		free (mb);
	}
}

/******************************************************************************
* This function reads the registry to get the path of iexplore.exe
******************************************************************************/
char * getIePath()
{
	// example of reading registry http://www.codersource.net/Win32/Win32Registry/RegistryOperationsusingWin32.aspx
	char lszValue[MAX_PATH];
	char *newValue = lszValue + 1;
	char *strkey;
	char path[MAX_PATH];
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_SZ;
	DWORD dwSize = MAX_PATH;
	returnStatus = RegOpenKeyEx(HKEY_CLASSES_ROOT,TEXT("applications\\iexplore.exe\\shell\\open\\command"), 0L, KEY_READ, &hKey);
	if (returnStatus ==  ERROR_SUCCESS)
	{
		returnStatus = RegQueryValueExA(hKey, NULL, NULL, &dwType, (LPBYTE)&lszValue, &dwSize);
		if(returnStatus == ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			if( ( strkey=strstr(lszValue, "%1" ) ) !=NULL)
				*(strkey=strkey-2)='\0';
			printf("\niexplorer.exe path is %s", newValue);
			// newValue was the easiest way I could find to remove the first char. I miss python
			return newValue;
		}
		else
		{
			printf("ERROR: Registry IE Path not Found");
		}
	}
	else 
	{
		printf("ERROR: Registry IE Path not Found");
	}
	RegCloseKey(hKey);
	return NULL;
}

/******************************************************************************
* This function scans a PID for memory that is marked as RWX. If the PID is 
* zero a dummy process of iexplore.exe is opened using CreateProcess  
******************************************************************************/
MEMBLOCK* create_scan ( unsigned int pid)
{
	char path[MAX_PATH];
	MEMBLOCK *mb_list = NULL;
	MEMORY_BASIC_INFORMATION meminfo;
	unsigned char *addr = 0;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	if ( pid )
	{
		// doesn't seem very bueno but it works
		pi.hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
	}
	else
	{
		// get the path of IE
		strcpy(path,getIePath());
		if(!CreateProcessA(path , NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi))
			printf("\nSorry! Broke on CreateProcess()\n\n");
		else
		{
			printf("\nDummy Process Started with PID %i", pi.dwProcessId);
		}
	}
	// we have our process
	if (pi.hProcess)
	{
		while (1)
		{
			// if 0 we have reached the end of readable memory. 
			if (VirtualQueryEx( pi.hProcess, addr, &meminfo, sizeof(meminfo)) == 0)
			{ // query addresses, reads all meomory including non-commited  
				break;
			}
			// if memory is marked as RWX
			if (meminfo.Protect & PAGE_EXECUTE_READWRITE)
			{
				MEMBLOCK *mb = create_memblock (pi.hProcess, &meminfo);
				if (mb)
				{ 
					mb->next = mb_list;
					mb_list = mb;
				}
			}
			addr = ( unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
		}

	}

	return mb_list;
}

/******************************************************************************
* This function cleans up a memory block 
******************************************************************************/
void free_scan (MEMBLOCK *mb_list)
{
	CloseHandle(mb_list->hProc);
	while ( mb_list)
	{
		MEMBLOCK *mb = mb_list;
		mb_list = mb_list->next;
		free_memblock (mb);
	}   

}

/******************************************************************************
* This function dumps the memory block to a file. The file name will be 
* formatted as Pid.0xAddress.bin in the working directory
******************************************************************************/
void dump_scan_info ( MEMBLOCK *mb_list, int pid)
{
	MEMBLOCK  *mb = mb_list;
	char *buffer = (char*) malloc(mb->size);

	// BUG 
	// The dump is currently dumping the memory size of the block, not the region size. 
	while (mb)
	{
		char *buffer = (char*) malloc(mb->size);
		FILE *fp;
		char filename[MAX_PATH];
		sprintf(filename, "%i.0x%08x.bin", pid, mb->addr);
		printf ("\nSuspicious Memory Block:\nAddr: 0x%08x Size:%d\r\n", mb->addr, mb->size);
		if (ReadProcessMemory(mb->hProc,(void*)mb->addr, buffer, mb->size, NULL) != 0)
		{
			fp=fopen(filename, "wb");
			printf ("Dumping Memory at 0x%08x to %s", mb->addr, filename );
			fwrite(buffer,1, mb->size, fp);
			fclose(fp);
		}
		else
			printf("Error Could Not Dump Memory");
		free(buffer);
		mb = mb->next;
	}
}

/******************************************************************************
* Main()
******************************************************************************/
int main(int argc, char *argv[])
{
	// PSLIST is a struct that contains the pid, process name and the next item in the linked list
	PSLIST *scannedps;
	printf("bkdump - simple RWX process dumper for commonly injected processes\n\t bkdump.exe 0 - to open a dummy iexplorer.exe\n\t bkdump.exe PID - to dump RWX Memory in a process\n\t bkdump.exe - to dump RWX memory of running firefox.exe, ie, \n\t explorer.exe, chrome.exe\n\t created by alexander.hanel\n"); 
	// Adjust Process Token
	if ( !EnableTokenPrivilege (SE_DEBUG_NAME) )
	{
		printf("EnableTokenPrivilege failed");
		return 0;
	}
	// check if there is an argument. The arugment should be the pid of the process to scan. 
	// If the PID is zero it will open up the dummy version of IE 
	// Todo: test for valid int
	if(argc == 2)
	{
		MEMBLOCK *scan = create_scan(atoi(argv[1]));
		if (scan)
		{
			dump_scan_info (scan, atoi(argv[1]));
			free_scan (scan);
		}
		printf("\n");
	}
	else
	{
		// scannedps will get a linked list that contains the pid, process name and the next item in the list
		scannedps = GetProcessList( );
		while( scannedps ){
			MEMBLOCK *scan = create_scan( scannedps->pid );
			if (scan)
			{
				printf( "\nDumping Process %s with PID %i", scannedps->psname, scannedps->pid );
				dump_scan_info ( scan, scannedps->pid );
				free_scan ( scan );
			}
			printf("\n");
			// get the next item in the linked list
			scannedps = scannedps->next ;
		}
	}
	return 0;
}
