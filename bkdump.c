#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

/*
Name:
	bkdump.exe

Version:
	0.1

Description:
	Starts iexplor.exe and then dumps any memory that has RWE rights. POC only tested on Win XP. 

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

*/ 

typedef struct _MEMBLOCK
{
	HANDLE hProc;
	unsigned char *addr;
	int size;
	unsigned char *buffer;
	struct _MEMBLOCK *next;
	
} MEMBLOCK;


MEMBLOCK* create_memblock (HANDLE hProc,  MEMORY_BASIC_INFORMATION *meminfo)
{	// used to create the membloc
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

unsigned int peek (HANDLE hProc, int data_size, unsigned int addr)
{
    unsigned int val = 0;
    if (ReadProcessMemory (hProc, (void*)addr, &val, data_size, NULL) == 0)
    {
        printf ("peek failed\r\n");
    }
    return val;
}

char * getIePath()
{
	// example of reading registry http://www.codersource.net/Win32/Win32Registry/RegistryOperationsusingWin32.aspx
	char lszValue[MAX_PATH];
	char **newValue = lszValue + 1;
	char *strkey;
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
			printf("iexplorer.exe path is %s", newValue);
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
	strcpy(path,getIePath());

	if(!CreateProcessA(path , NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &si, &pi))
		printf("\nSorry! Broke on CreateProcess()\n\n");
	else
	{
		printf("\nDummy Process Started");
	}
	if (pi.hProcess)
	{
		while (1)
		{
			if (VirtualQueryEx(pi.hProcess, addr, &meminfo, sizeof(meminfo)) == 0)
			{ // query addresses, reads all meomory including non-commited  
				break;
			}

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

void dump_scan_info ( MEMBLOCK *mb_list)
{
	MEMBLOCK  *mb = mb_list;
	char *buffer = (char*) malloc(mb->size);

	while (mb)
	{
		char *buffer = (char*) malloc(mb->size);
		FILE *fp;
		char filename[15];
		sprintf(filename, "0x%08x.bin", mb->addr);
		fp=fopen(filename, "wb");
		printf ("\nSuspicious Memory Block:\nAddr: 0x%08x Size:%d\r\n", mb->addr, mb->size);
		if (ReadProcessMemory(mb->hProc,(void*)mb->addr, buffer, mb->size, NULL) != 0)
		{
			printf ("Dumping Memory at 0x%08x", mb->addr);
			fwrite(buffer,1, mb->size, fp);
			fclose(fp);

		}
		else
			printf("Error Could Not Dump Memory");
		mb = mb->next;
	}
}

int main(int argc, char *argv[])
{
	
	MEMBLOCK *scan = create_scan(0);
	if (scan)
	{
		dump_scan_info (scan);
		free_scan (scan);
	}
	/*
	
	*/
	return 0;
}
