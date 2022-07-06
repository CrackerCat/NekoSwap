#ifndef NEKO_CONTROL_H
#define NEKO_CONTROL_H

#include <Windows.h>
#include <winternl.h>
#include <thread>

#pragma warning(disable : 4312)

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

class NekoControl
{
private:
	HANDLE targetProcessPid;
	PVOID currentProcess;
	PVOID targetProcess;

	DWORD64(__stdcall* PsLookupProcessByProcessId)(HANDLE processId, void** process) = nullptr;
	DWORD64(__stdcall* MmCopyVirtualMemory)(PVOID sourceProcess, PVOID sourceAddress, PVOID targetProcess, PVOID targetAddress, SIZE_T bufferSize, CCHAR previousMode, PSIZE_T returnSize) = nullptr;
public:
	void Init()
	{
		HMODULE targetModule = LoadLibraryA("win32u.dll");
		printf("win32u.dll: 0x%p\n", targetModule);

		*reinterpret_cast<void**>(&PsLookupProcessByProcessId) = GetProcAddress(targetModule, "NtUserSetGestureConfig");
		*reinterpret_cast<void**>(&MmCopyVirtualMemory) = GetProcAddress(targetModule, "NtUserSetSensorPresence");

		if (PsLookupProcessByProcessId == nullptr || MmCopyVirtualMemory == nullptr)
		{
			printf("Failed to resolve functions!\n");
			getchar();
			return;
		}

		// no printf no work???
		// volatile is missing somewhere i guess
		printf("NtUserSetGestureConfig: 0x%p\n", PsLookupProcessByProcessId);
		printf("NtUserSetSensorPresence: 0x%p\n", MmCopyVirtualMemory);

		DWORD64 status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(GetCurrentProcessId()), &currentProcess);
		if (status != 0)
		{
			printf("Failed to get current process EPROCESS (0x%p)!\n", status);
			getchar();
			return;
		}

		printf("Client EPROCESS: 0x%p\n", currentProcess);
	}

	void SetTarget(HANDLE pid)
	{
		targetProcessPid = pid;

		DWORD64 status = PsLookupProcessByProcessId(targetProcessPid, &targetProcess);
		if (status != 0)
		{
			printf("Failed to get target process EPROCESS (0x%p)!\n", status);
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
		SIZE_T bytesCopied;
		DWORD64 status = MmCopyVirtualMemory(targetProcess, source, currentProcess, destination, size, 0 /* KernelMode */, &bytesCopied);
		return status == 0;
	}

	bool WriteMemory(PVOID source, PVOID destination, SIZE_T size)
	{
		SIZE_T bytesCopied;
		DWORD64 status = MmCopyVirtualMemory(currentProcess, source, targetProcess, destination, size, 0, &bytesCopied);
		return status == 0;
	}

	PVOID GetModule(const wchar_t* moduleName)
	{
		HANDLE targetProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, reinterpret_cast<DWORD>(targetProcessPid));
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