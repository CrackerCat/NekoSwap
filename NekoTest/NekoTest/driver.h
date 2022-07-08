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
	PVOID returnSizeBuffer;

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
		MmCopyVirtualMemory = reinterpret_cast<MmCopyVirtualMemory_t>(GetProcAddress(targetModule, "NtUserDrawCaptionTemp"));

		if (PsLookupProcessByProcessId == nullptr || MmCopyVirtualMemory == nullptr)
		{
			printf("Failed to resolve functions!\n");
			getchar();
			return;
		}

		printf("NtUserSetGestureConfig: 0x%p\n", PsLookupProcessByProcessId);
		printf("NtUserSetSensorPresence: 0x%p\n", MmCopyVirtualMemory);

		DWORD64 status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(GetCurrentProcessId()), &currentProcess);
		if (status != 0)
		{
			printf("Failed to get current process EPROCESS (0x%p)!\n", reinterpret_cast<PVOID>(status));
			getchar();
			return;
		}

		printf("Client EPROCESS: 0x%p\n", currentProcess);

		// the parameter that passes the return size parameter copied only 4 bytes
		// so it has to be someone in the 32bit integer region
		returnSizeBuffer = VirtualAlloc(reinterpret_cast<PVOID>(0x100000), 8, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!returnSizeBuffer)
		{
			printf("Failed to allocate memory for return buffer!\n");
			getchar();
			return;
		}

		if (reinterpret_cast<DWORD64>(returnSizeBuffer) + 8 > UINT32_MAX)
		{
			printf("Return buffer memory allocated too high!\n");
			getchar();
			return;
		}

		printf("Return buffer: 0x%p\n", returnSizeBuffer);
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

		printf("ReadMemory:\n\ttargetProcess: 0x%p\n\tsource: 0x%p\n\tcurrentProcess: 0x%p\n\tdestination: 0x%p\n\tsize: %llu\n\tbytesCopied: 0x%p\n", targetProcess, source, currentProcess, destination, size, returnSizeBuffer);
		DWORD64 status = MmCopyVirtualMemory(targetProcess, source, currentProcess, destination, size, 0 /* KernelMode */, returnSizeBuffer);
		return status == 0;
	}

	bool WriteMemory(PVOID source, PVOID destination, SIZE_T size)
	{
		if (!CheckAddress(source))
			return false;

		if (!CheckAddress(destination))
			return false;

		printf("WriteMemory:\n\ttargetProcess: 0x%p\n\tsource: 0x%p\n\tcurrentProcess: 0x%p\n\tdestination: 0x%p\n\tsize: %llu\n", targetProcess, source, currentProcess, destination, size);

		DWORD64 status = MmCopyVirtualMemory(currentProcess, source, targetProcess, destination, size, 0, returnSizeBuffer);
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