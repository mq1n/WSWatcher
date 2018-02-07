#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <ImageHlp.h>
#pragma comment(lib, "imagehlp.lib")

#define NtCurrentProcess					((HANDLE)(LONG_PTR)-1)
#define STATUS_INFO_LENGTH_MISMATCH			((NTSTATUS)0xC0000004)
#define STATUS_UNSUCCESSFUL					((NTSTATUS)0xC0000001L)
#define STATUS_BUFFER_TOO_SMALL				((NTSTATUS)0xC0000023L)
#define STATUS_NO_MORE_ENTRIES				((NTSTATUS)0x8000001AL)
#define NT_SUCCESS(Status)					(((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* lpNtQueryInformationProcess)(HANDLE, LONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);

static lpNtQueryInformationProcess	NtQueryInformationProcess;
static lpNtQueryInformationThread	NtQueryInformationThread;

typedef DWORD KPRIORITY;
typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

void ShowWSChanges()
{
	auto dwWatchInfoSize = DWORD(sizeof(PSAPI_WS_WATCH_INFORMATION_EX) * 1000);
	auto WatchInfoEx = (PPSAPI_WS_WATCH_INFORMATION_EX)malloc(dwWatchInfoSize);
	if (!WatchInfoEx)
	{
		printf("WatchInfoEx allocation fail! Size: %u Error: %u\n", dwWatchInfoSize, GetLastError());
		return;
	}

	while (1)
	{
		memset(WatchInfoEx, 0, dwWatchInfoSize);

		if (!K32GetWsChangesEx(NtCurrentProcess, WatchInfoEx, &dwWatchInfoSize))
		{
			auto dwErrorCode = GetLastError();

			if (dwErrorCode == ERROR_NO_MORE_ITEMS)
			{
				Sleep(1);
				continue;
			}

			if (dwErrorCode != ERROR_INSUFFICIENT_BUFFER)
			{
				printf("GetWsChangesEx fail! Error: %u\n", dwErrorCode);
				free(WatchInfoEx);
				return;
			}

			dwWatchInfoSize *= 2;

			WatchInfoEx = (PPSAPI_WS_WATCH_INFORMATION_EX)realloc(WatchInfoEx, dwWatchInfoSize);
			if (!WatchInfoEx)
			{
				printf("WatchInfoEx reallocation fail! Size: %u Error: %u\n", dwWatchInfoSize, GetLastError());
				if (WatchInfoEx)
					free(WatchInfoEx);
				return;
			}

			continue;
		}

		for (std::size_t i = 0;; ++i)
		{
			PPSAPI_WS_WATCH_INFORMATION_EX info = &WatchInfoEx[i];
			if (info->BasicInfo.FaultingPc == NULL)
				break;

			printf("-----------------------------------\n");
			printf("TID: %p Pc: %p Va: %p\n", (LPVOID)(info->FaultingThreadId), info->BasicInfo.FaultingPc, info->BasicInfo.FaultingVa);

			auto hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)info->FaultingThreadId);
			printf("hThread: %p\n", hThread);

			if (hThread && hThread != INVALID_HANDLE_VALUE)
			{
				THREAD_BASIC_INFORMATION ThreadInfo;
				auto ntStatus = NtQueryInformationThread(hThread, 0 /* ThreadBasicInformation */, &ThreadInfo, sizeof(ThreadInfo), NULL);
				printf("ntStatus: %u\n", ntStatus);

				if (NT_SUCCESS(ntStatus))
				{
					auto dwPID = (DWORD64)ThreadInfo.ClientId.UniqueProcess;
					auto dwCurrPID = GetCurrentProcessId();
					printf("PID: %I64u-%lu\n", dwPID, dwCurrPID);

					if (dwPID != GetCurrentProcessId())
					{
						auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)dwPID);
						printf("hProcess: %p\n", hProcess);

						if (hProcess && hProcess != INVALID_HANDLE_VALUE)
						{
							LPVOID pCurrentThreadAddress = 0;
							ntStatus = NtQueryInformationThread(hThread, 9 /* ThreadQuerySetWin32StartAddress */, &pCurrentThreadAddress, sizeof(pCurrentThreadAddress), NULL);
							printf("Ntstatus: %u Start adress: %p\n", ntStatus, pCurrentThreadAddress);

							wchar_t wszImagePath[MAX_PATH];
							if (K32GetMappedFileNameW(hProcess, pCurrentThreadAddress, wszImagePath, MAX_PATH) != 0)
								printf("Process name: %ls\n", wszImagePath);

							CloseHandle(hProcess);
						}
					}
				}
				CloseHandle(hThread);
			}
		}
	}

}

int main()
{
	auto hNtdll = LoadLibraryA("ntdll");
	if (!hNtdll) {
		printf("hNtdll fail! Last error: %u\n", GetLastError());
		return 0;
	}

	NtQueryInformationProcess = (lpNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		printf("NtQueryInformationProcess fail! Last error: %u\n", GetLastError());
		return 0;
	}
	NtQueryInformationThread = (lpNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
	if (!NtQueryInformationThread) {
		printf("NtQueryInformationThread fail! Last error: %u\n", GetLastError());
		return 0;
	}

#if defined(_M_IX86) // Not supported
	BOOL Wow64Process = FALSE;
	if (IsWow64Process(NtCurrentProcess, &Wow64Process) && Wow64Process)
	{
		printf("This process cannot be run under Wow64.\n");
		return 0;
	}
#endif

	if (!K32InitializeProcessForWsWatch(NtCurrentProcess))
	{
		printf("InitializeProcessForWsWatch fail. Error: %u\n", GetLastError());
		return 0;
	}

	ShowWSChanges();
	
	Sleep(INFINITE);
	return 0;
}

