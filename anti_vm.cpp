#include<WinSock2.h>
#include<iphlpapi.h>
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>
#include<tlhelp32.h>
#pragma comment(lib, "IPHLPAPI.lib")

int CheckNOFCores()
{
	unsigned int cores = 0;

	__asm
	{
		MOV EAX, DWORD PTR FS:[0x30] // PEB
		MOV EAX, DWORD PTR DS:[EAX + 0x64] // NumberOfProcessors
		CMP EAX, 0x1
		JE OneCore
		JMP DONE

		OneCore: MOV cores, 1

		DONE: nop
	}

	return cores;
}

void MagicNumber()
{
	unsigned int vm_flag = 1;

	__asm
	{
		MOV EAX, 0x564D5868; 'VMXh'
		MOV EDX, 0x5658; 'VX(port)'
		in EAX, DX; 'Read input from that port'
		CMP EBX, 0x564D5868
		SETZ ECX; 'if successful -> flag = 0'
		MOV vm_flag, ECX
	}

	if (vm_flag == 0)
		printf("VMware Detected.");
	else
		printf("VMware NOT detected\n");
}

BOOL FindInRegistry()
{
	HKEY hKey;
	DWORD dwType;
	DWORD dwDataSize = MAXDWORD;
	BOOL status = FALSE;
	char lszValue[255] = { 0 };

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0L, KEY_READ, &hKey);

	RegQueryValueEx(hKey, L"0", NULL, &dwType, (BYTE*)lszValue, &dwDataSize);

	if (strstr(lszValue, "VMware"))
	{
		status = TRUE;
	}
	else {
		RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0L, KEY_READ, &hKey);

		RegQueryValueEx(hKey, L"SystemBiosVersion", NULL, &dwType, (BYTE*)lszValue, &dwDataSize);

		if (strstr(lszValue, "VirtualBox"))
		{
			status = TRUE;
		}
	}

	RegCloseKey(hKey);
	return status;
}

int FindMountPoints()
{
	int i;
	TCHAR lpFilename[MAX_PATH];
	char upperFileName[MAX_PATH];

	GetModuleFileName(NULL, lpFilename, MAX_PATH);

	for (i = 0; i < MAX_PATH; i++) // Convert to Uppercase letters
	{
		upperFileName[i] = toupper(upperFileName[i]);
	}

	if (strstr(upperFileName, "\\SANDBOX") != NULL)
	{
		return TRUE;
	}

	if (strstr(upperFileName, "\\VIRUS") != NULL)
	{
		return TRUE;
	}

	if (strstr(upperFileName, "\\SAMPLE") != NULL)
	{
		return TRUE;
	}

	return FALSE;
}

void CheckVMwareProcesses(int writelogs)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE) // Looping over the processes list
		{
			if (lstrcmpi(entry.szExeFile, L"vmtoolsd.exe") == 0)
			{
				printf("VMware process has been found!");
			}
			else if (lstrcmpi(entry.szExeFile, L"vmacthlp.exe") == 0)
			{
				printf("Another VMware process has been found!");
			}
		}
	}

	CloseHandle(snapshot);
}

bool ModuleCheck() 
{
	LPCWSTR sModules[7] = { L"sbiedll.dll", L"api_log.dll",
		L"dir_watch.dll", L"dbghelp.dll",
		L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll" };

	for (int i = 0; i < 7; i++)
	{
		if (GetModuleHandle(sModules[i])) // Check if this module already exists in the memory
		{
			return TRUE; // Return TRUE if we are in a Virual Machine.
		}
	}
	return FALSE;
}

BOOL isLessThan60()
{
	ULARGE_INTEGER total_bytes;

	if (GetDiskFreeSpaceExA("C:\\", NULL, &total_bytes, NULL))
	{
		if (total_bytes.QuadPart / 1073741824 <= 60) /* <= 60 GB */
			return TRUE;
	}
	return FALSE;
}

BOOL IsSharedFolder()
{
	unsigned long pnsize = 0x1000;
	LPWSTR provider = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, pnsize);
	BOOL status = FALSE;

	int retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
	if (retv == NO_ERROR)
	{
		if (lstrcmpi(provider, L"VirtualBox Shared Folders") == 0) {
			status = TRUE;
		}
		else {
			status = FALSE;
		}
	}

	LocalFree(provider);
	return status;
}

int IsVMwareMACAddress() {
	unsigned long alist_size = 0, ret;

	ret = GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &alist_size);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		IP_ADAPTER_ADDRESSES* palist = (IP_ADAPTER_ADDRESSES*)LocalAlloc(LMEM_ZEROINIT, alist_size);
		if (palist) {
			GetAdaptersAddresses(AF_UNSPEC, 0, 0, palist, &alist_size);
			char mac[6] = { 0 };
			while (palist) {
				if (palist->PhysicalAddressLength == 0x6) {
					memcpy(mac, palist->PhysicalAddress, 0x6);

					if (!memcmp("\x00\x05\x69", mac, 3)) { /* Reading the first 3 bytes */
						LocalFree(palist);
						return TRUE;
					}

					if (!memcmp("\x00\x0C\x29", mac, 3)) { 
						LocalFree(palist);
						return TRUE;
					}

					if (!memcmp("\x00\x1C\x14", mac, 3)) { 
						LocalFree(palist);
						return TRUE;
					}

					if (!memcmp("\x00\x50\x56", mac, 3)) {
						LocalFree(palist);
						return TRUE;
					}
				}
				palist = palist->Next;
			}
			LocalFree(palist);
		}
	}
	return FALSE;
}

int main()
{
	return EXIT_SUCCESS;
}
