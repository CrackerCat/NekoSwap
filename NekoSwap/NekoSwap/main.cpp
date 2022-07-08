#include "global.h"

/*
 * WARNING
 * Windows implementation of syscalls is not passing the entire stack
 * to the kernel. Only the given amount of argument. Always verify that
 * the original function has enough arguments or you will be getting
 * garbage (5+ arg is passed on stack).
 */

DWORD64* GetFunctionFromTable(DWORD64 tableEntry, int tableIndex, int functionIndex)
{
	PROTECT_ULTRA();
	DWORD64 functionTable = *reinterpret_cast<DWORD64*>(tableEntry + (tableIndex * sizeof(DWORD64)));
	DWORD64* functionPointer = reinterpret_cast<DWORD64*>(functionTable + (functionIndex * sizeof(DWORD64)));
	PROTECT_END();
	return functionPointer;
}

NTSTATUS TestCallback(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6, PVOID arg7)
{
	//__debugbreak();
	DbgPrintEx(0, 0, "arg1: 0x%p arg2: 0x%p arg3: 0x%p arg4: 0x%p arg5: 0x%p arg6: 0x%p arg7: 0x%p\n", arg1, arg2, arg3, arg4, arg5, arg6, arg7);
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

	//DWORD64* functionNtUserSetSensorPresence = GetFunctionFromTable(table, Defines::ext_ms_win_core_win32k_fulluser_l1, Defines::NtUserSetSensorPresence);
	DWORD64* functionNtUserSetSensorPresence = GetFunctionFromTable(table, Defines::ext_ms_win_core_win32k_fulluser_l1, Defines::NtUserDrawCaptionTemp);
	*functionNtUserSetSensorPresence = reinterpret_cast<DWORD64>(&Utils::MmCopyVirtualMemory);
	//*functionNtUserSetSensorPresence = reinterpret_cast<DWORD64>(&TestCallback);

	// TODO: disable APCs
	// TODO: registry check

	PROTECT_END();
	return STATUS_SUCCESS;
}