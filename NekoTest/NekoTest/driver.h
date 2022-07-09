#ifndef NEKO_CONTROL_H
#define NEKO_CONTROL_H

/*
 * WARNING
 * Disable Control Flow Guard and Security Check
 */

#include <Windows.h>
#include <winternl.h>
#include <thread>

#pragma warning(disable : 4312)
#pragma warning(disable : 4244)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

#define MAX_VIRTUAL_USERMODE 0x7FFFFFFFFFFF
#define MIN_VIRTUAL_USERMODE 0x10000

class NekoControl
{
private:
	HANDLE targetProcessPid;
	PVOID currentProcess;
	PVOID targetProcess;
	PVOID kernelMemory;

	// KTHREAD -> MiscFlags
	const uint64_t OffsetMiscFlags = 0x74;

	typedef struct _Flags
	{
		union
		{
			struct
			{
				ULONG AutoBoostActive : 1;                                        //0x74
				ULONG ReadyTransition : 1;                                        //0x74
				ULONG WaitNext : 1;                                               //0x74
				ULONG SystemAffinityActive : 1;                                   //0x74
				ULONG Alertable : 1;                                              //0x74
				ULONG UserStackWalkActive : 1;                                    //0x74
				ULONG ApcInterruptRequest : 1;                                    //0x74
				ULONG QuantumEndMigrate : 1;                                      //0x74
				ULONG Spare1 : 1;                                                 //0x74
				ULONG TimerActive : 1;                                            //0x74
				ULONG SystemThread : 1;                                           //0x74
				ULONG ProcessDetachActive : 1;                                    //0x74
				ULONG CalloutActive : 1;                                          //0x74
				ULONG ScbReadyQueue : 1;                                          //0x74
				ULONG ApcQueueable : 1;                                           //0x74
				ULONG ReservedStackInUse : 1;                                     //0x74
				ULONG Spare2 : 1;                                                 //0x74
				ULONG TimerSuspended : 1;                                         //0x74
				ULONG SuspendedWaitMode : 1;                                      //0x74
				ULONG SuspendSchedulerApcWait : 1;                                //0x74
				ULONG CetUserShadowStack : 1;                                     //0x74
				ULONG BypassProcessFreeze : 1;                                    //0x74
				ULONG CetKernelShadowStack : 1;                                   //0x74
				ULONG StateSaveAreaDecoupled : 1;                                 //0x74
				ULONG IsolationWidth : 1;                                         //0x74
				ULONG Reserved : 7;                                               //0x74
			} BitFields;
			LONG MiscFlags;                                                     //0x74
		} Internal;
	} Flags;

	typedef PVOID(__stdcall* ExAllocatePool_t)(DWORD64 PoolType, SIZE_T NumberOfBytes);
	volatile ExAllocatePool_t ExAllocatePool = nullptr;
	typedef PVOID(__stdcall* RtlCopyMemory_t)(void* destination, void* source, size_t length);
	volatile RtlCopyMemory_t KernelRtlCopyMemory = nullptr;
	typedef PVOID(__stdcall* PsGetCurrentThread_t)();
	volatile PsGetCurrentThread_t PsGetCurrentThread = nullptr;
	typedef DWORD64(__stdcall* PsLookupProcessByProcessId_t)(HANDLE processId, void** process);
	volatile PsLookupProcessByProcessId_t PsLookupProcessByProcessId = nullptr;
	typedef DWORD64(__stdcall* MmCopyVirtualMemory_t)(PVOID sourceProcess, PVOID sourceAddress, PVOID targetProcess, PVOID targetAddress, SIZE_T bufferSize, CCHAR previousMode, PVOID returnSize);
	volatile MmCopyVirtualMemory_t MmCopyVirtualMemory = nullptr;

	bool CheckAddress(PVOID address)
	{
		if (reinterpret_cast<DWORD64>(address) > MAX_VIRTUAL_USERMODE)
			return false;

		if (reinterpret_cast<DWORD64>(address) < MIN_VIRTUAL_USERMODE)
			return false;

		return true;
	}
public:
	void Init()
	{
		// if not loaded, the syscalls will literally shit itself
		HMODULE userModule = LoadLibraryA("user32.dll");
		if (!userModule)
			return;
		printf("user32.dll: 0x%p\n", userModule);

		HMODULE targetModule = LoadLibraryA("win32u.dll");
		if (!targetModule)
			return;
		printf("win32u.dll: 0x%p\n", targetModule);

		PsLookupProcessByProcessId = reinterpret_cast<PsLookupProcessByProcessId_t>(GetProcAddress(targetModule, "NtUserSetGestureConfig"));
		KernelRtlCopyMemory = reinterpret_cast<RtlCopyMemory_t>(GetProcAddress(targetModule, "NtUserGetGestureConfig"));
		ExAllocatePool = reinterpret_cast<ExAllocatePool_t>(GetProcAddress(targetModule, "NtUserSetSensorPresence"));
		PsGetCurrentThread = reinterpret_cast<PsGetCurrentThread_t>(GetProcAddress(targetModule, "NtUserSetSystemCursor"));
		MmCopyVirtualMemory = reinterpret_cast<MmCopyVirtualMemory_t>(GetProcAddress(targetModule, "NtGdiGetEmbUFI"));

		if (!PsLookupProcessByProcessId
			|| !MmCopyVirtualMemory
			|| !ExAllocatePool
			|| !KernelRtlCopyMemory
			|| !PsGetCurrentThread)
		{
			printf("Failed to resolve functions!\n");
			getchar();
			return;
		}

		printf("NtUserSetGestureConfig: 0x%p\n", PsLookupProcessByProcessId);
		printf("NtGdiGetEmbUFI: 0x%p\n", MmCopyVirtualMemory);

		DWORD64 status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(GetCurrentProcessId()), &currentProcess);
		if (status != 0)
		{
			printf("Failed to get current process EPROCESS (0x%p)!\n", reinterpret_cast<PVOID>(status));
			getchar();
			return;
		}

		printf("Client EPROCESS: 0x%p\n", currentProcess);

		kernelMemory = ExAllocatePool(0, 128);
		if (!kernelMemory)
		{
			printf("Failed to allocate non paged memory!\n");
			getchar();
			return;
		}

		printf("Non paged memory: 0x%p\n", kernelMemory);
	}

	void ModifyThread()
	{
		PBYTE currentThread = static_cast<PBYTE>(PsGetCurrentThread());
		printf("Current ETHREAD: 0x%p\n", currentThread);

		Flags* flags = static_cast<Flags*>(VirtualAlloc(nullptr, sizeof(Flags), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!flags)
		{
			printf("Failed to allocate memory!\n");
			return;
		}
		 
		KernelRtlCopyMemory(flags, currentThread + OffsetMiscFlags, sizeof(Flags));

		printf("flags->AutoBoostActive: %u\n", static_cast<UINT>(flags->Internal.BitFields.AutoBoostActive));
		printf("flags->ReadyTransition: %u\n", static_cast<UINT>(flags->Internal.BitFields.ReadyTransition));
		printf("flags->WaitNext: %u\n", static_cast<UINT>(flags->Internal.BitFields.WaitNext));
		printf("flags->UserStackWalkActive: %u\n", static_cast<UINT>(flags->Internal.BitFields.UserStackWalkActive));
		printf("flags->SystemThread: %u\n", static_cast<UINT>(flags->Internal.BitFields.SystemThread));
		printf("flags->ApcQueueable: %u\n", static_cast<UINT>(flags->Internal.BitFields.ApcQueueable));

		flags->Internal.BitFields.ApcQueueable = false;

		KernelRtlCopyMemory(currentThread + OffsetMiscFlags, flags, sizeof(Flags));

		printf("APCs disabled for current thread\n");
	}

	void SetTarget(HANDLE pid)
	{
		targetProcessPid = pid;

		DWORD64 status = PsLookupProcessByProcessId(targetProcessPid, &targetProcess);
		if (status != 0)
		{
			printf("Failed to get target process EPROCESS (0x%p)!\n", reinterpret_cast<PVOID>(status));
			getchar();
			return;
		}

		printf("Target EPROCESS: 0x%p\n", targetProcess);
	}

	bool Check()
	{
		return reinterpret_cast<DWORD64>(currentProcess) > 0x7FFFFFFFFFFF;
	}

	bool ReadMemory(PVOID source, PVOID destination, SIZE_T size)
	{
		if (!CheckAddress(source))
			return false;

		if (!CheckAddress(destination))
			return false;

		//printf("ReadMemory:\n\ttargetProcess: 0x%p\n\tsource: 0x%p\n\tcurrentProcess: 0x%p\n\tdestination: 0x%p\n\tsize: %llu\n", targetProcess, source, currentProcess, destination, size);
		DWORD64 status = MmCopyVirtualMemory(targetProcess, source, currentProcess, destination, size, 0 /* KernelMode */, kernelMemory);
		return status == 0;
	}

	bool WriteMemory(PVOID source, PVOID destination, SIZE_T size)
	{
		if (!CheckAddress(source))
			return false;

		if (!CheckAddress(destination))
			return false;

		//printf("WriteMemory:\n\ttargetProcess: 0x%p\n\tsource: 0x%p\n\tcurrentProcess: 0x%p\n\tdestination: 0x%p\n\tsize: %llu\n", targetProcess, source, currentProcess, destination, size);
		DWORD64 status = MmCopyVirtualMemory(currentProcess, source, targetProcess, destination, size, 0, kernelMemory);
		return status == 0;
	}

	PVOID GetModule(const wchar_t* moduleName)
	{
		HANDLE targetProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, *reinterpret_cast<DWORD*>(&targetProcessPid));
		if (!targetProcessHandle || targetProcessHandle == INVALID_HANDLE_VALUE)
			return nullptr;

		DWORD64 currentAddress = 0;
		MEMORY_BASIC_INFORMATION memoryInformation;
		while (VirtualQueryEx(targetProcessHandle, reinterpret_cast<PVOID>(currentAddress), &memoryInformation, sizeof(MEMORY_BASIC_INFORMATION64)))
		{
			if (memoryInformation.Type == MEM_MAPPED || memoryInformation.Type == MEM_IMAGE)
			{
				constexpr SIZE_T bufferSize = 1024;
				PVOID buffer = malloc(bufferSize);

				SIZE_T bytesOut;
				NTSTATUS status = NtQueryVirtualMemory(targetProcessHandle, memoryInformation.BaseAddress, MemoryMappedFilenameInformation, buffer, bufferSize, &bytesOut);
				if (status == 0)
				{
					UNICODE_STRING* stringBuffer = static_cast<UNICODE_STRING*>(buffer);
					if (wcsstr(stringBuffer->Buffer, moduleName) && !wcsstr(stringBuffer->Buffer, L".mui"))
					{
						free(buffer);
						CloseHandle(targetProcessHandle);
						return memoryInformation.BaseAddress;
					}
				}

				free(buffer);
			}

			currentAddress = reinterpret_cast<DWORD64>(memoryInformation.BaseAddress) + memoryInformation.RegionSize;
		}

		CloseHandle(targetProcessHandle);
		return nullptr;
	}

	template<typename T>
	T Read(DWORD64 address)
	{
		T val = T();
		ReadMemory((PVOID)address, &val, sizeof(T));
		return val;
	}

	template<typename T>
	void Write(DWORD64 address, T value)
	{
		WriteMemory(&value, (PVOID)address, sizeof(T));
	}
};

extern NekoControl* g_Drv;

#endif