#include "global.h"

DWORD64* GetFunctionFromTable(DWORD64 tableEntry, Defines::TableList tableIndex, Defines::FunctionList functionIndex)
{
	PROTECT_ULTRA();
	DWORD64 functionTable = *reinterpret_cast<DWORD64*>(tableEntry + (tableIndex * sizeof(DWORD64)));
	DWORD64* functionPointer = reinterpret_cast<DWORD64*>(functionTable + (functionIndex * sizeof(DWORD64)));
	PROTECT_END();
	return functionPointer;
}

NTSTATUS TestMmCopyVirtualMemory(PEPROCESS sourceProcess, PVOID sourceAddress, PEPROCESS targetProcess, PVOID targetAddress, SIZE_T bufferSize, KPROCESSOR_MODE previousMode, PSIZE_T returnSize)
{
	DbgPrintEx(0, 0, "[NekoSwap] sourceProcess: 0x%p sourceAddress:0x%p targetProcess: 0x%p targetAddress: 0x%p bufferSize: %llu previousMode: %i returnSize: 0x%p\n", sourceProcess, sourceAddress, targetProcess, targetAddress, bufferSize, (int)previousMode, returnSize);
	return STATUS_SUCCESS;
}

NTSTATUS EntryPoint()
{
	PROTECT_ULTRA();
	PVOID moduleBase = Utils::GetModuleBase(E("win32k.sys"));
	if (!moduleBase)
		return STATUS_NOT_FOUND;

	// cmp     cs:off_FFFFF97FFF05B078, 0
	// jz      short loc_FFFFF97FFF001418
	// xor     esi, esi
	// lea     r14, Win32kApiSetTable
	// xor     edi, edi
	DWORD64 tableScan = Utils::FindPatternImage(moduleBase, E("48 83 3D ? ? ? ? ? 74 41 33 F6 4C 8D 35 ? ? ? ? 33 FF"));
	if (!tableScan)
		return STATUS_INVALID_PARAMETER;

	DWORD64 table = tableScan + 19 + *reinterpret_cast<int*>(tableScan + 15);

	DWORD64* functionNtUserSetGestureConfig = GetFunctionFromTable(table, Defines::ext_ms_win_core_win32k_fulluser_l1, Defines::NtUserSetGestureConfig);
	*functionNtUserSetGestureConfig = reinterpret_cast<DWORD64>(&PsLookupProcessByProcessId);

	DWORD64* functionNtUserSetSensorPresence = GetFunctionFromTable(table, Defines::ext_ms_win_core_win32k_fulluser_l1, Defines::NtUserSetSensorPresence);
	//*functionNtUserSetSensorPresence = reinterpret_cast<DWORD64>(&Utils::MmCopyVirtualMemory);
	*functionNtUserSetSensorPresence = reinterpret_cast<DWORD64>(&TestMmCopyVirtualMemory);

	// TODO: disable APCs
	// TODO: registry check

	PROTECT_END();
	return STATUS_SUCCESS;
}