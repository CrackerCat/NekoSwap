#include "global.h"

char* Utils::Compare(const char* haystack, const char* needle)
{
    PROTECT_MUTATE();
    do
    {
        const char* h = haystack;
        const char* n = needle;
        while (tolower(static_cast<unsigned char>(*h)) == tolower(static_cast<unsigned char>(*n)) && *n)
        {
            h++;
            n++;
        }

        if (*n == 0)
            return const_cast<char*>(haystack);
    } while (*haystack++);
    PROTECT_END();
    return nullptr;
}

PVOID Utils::GetModuleBase(const char* moduleName)
{
    PROTECT_ULTRA();
    PVOID address = nullptr;
    ULONG size = 0;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return nullptr;

    PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));
    if (!moduleList)
        return nullptr;

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
    if (!NT_SUCCESS(status))
        goto end;

    for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
    {
        DWORD64 pointer = (DWORD64)&moduleList->Modules[i];
        pointer += sizeof(SYSTEM_MODULE);
        if (pointer > ((DWORD64)moduleList + size))
            break;

        SYSTEM_MODULE module = moduleList->Modules[i];
        module.ImageName[255] = '\0';
        if (Compare(module.ImageName, moduleName))
        {
            address = module.Base;
            break;
        }
    }

end:
    ExFreePool(moduleList);
    PROTECT_END();
    return address;
}

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))
DWORD64 Utils::FindPattern(void* baseAddress, DWORD64 size, const char* pattern)
{
    PROTECT_MUTATE();
    BYTE* firstMatch = nullptr;
    const char* currentPattern = pattern;

    BYTE* start = static_cast<BYTE*>(baseAddress);
    BYTE* end = start + size;

    for (BYTE* current = start; current < end; current++)
    {
        BYTE byte = currentPattern[0]; if (!byte) return reinterpret_cast<DWORD64>(firstMatch);
        if (byte == '\?' || *static_cast<BYTE*>(current) == GET_BYTE(byte, currentPattern[1]))
        {
            if (!firstMatch) firstMatch = current;
            if (!currentPattern[2]) return reinterpret_cast<DWORD64>(firstMatch);
            ((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
        }
        else
        {
            currentPattern = pattern;
            firstMatch = nullptr;
        }
    }

    PROTECT_END();
    return 0;
}

DWORD64 Utils::FindPatternImage(void* base, const char* pattern, bool page)
{
    PROTECT_MUTATE();
    DWORD64 match = 0;

    PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<DWORD64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
    for (USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i)
    {
        PIMAGE_SECTION_HEADER section = &sections[i];
        if (memcmp(section->Name, E(".text"), 5) == 0)
        {
            match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<DWORD64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
            if (match)
                break;
        }

        if (page)
        {
            if (*reinterpret_cast<DWORD32*>(section->Name) == 'EGAP')
            {
                match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<DWORD64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
                if (match)
                    break;
            }
        }
    }

    PROTECT_END();
    return match;
}

PVOID Utils::AlignedAlloc(size_t size, size_t alignment)
{
    // https://sites.google.com/site/ruslancray/lab/bookshelf/interview/ci/low-level/write-an-aligned-malloc-free-function
    void* p1;
    void** p2;
    size_t offset = alignment - 1 + sizeof(void*);
    if ((p1 = ExAllocatePool(NonPagedPool, size + offset)) == nullptr)
        return nullptr;
    p2 = reinterpret_cast<void**>((reinterpret_cast<size_t>(p1) + offset) & ~(alignment - 1));
    p2[-1] = p1;
    return p2;
}

void Utils::AlignedFree(PVOID pointer)
{
    ExFreePool((static_cast<void**>(pointer))[-1]);
}