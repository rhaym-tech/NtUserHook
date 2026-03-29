#include <includes.h>

uintptr_t PatternScan(uintptr_t base, size_t size, const char* pattern, const char* mask)  {
    auto check = [](const char* data, const char* pattern, const char* mask) {
        for (; *mask; ++mask, ++data, ++pattern) {
            if (*mask == 'x' && *data != *pattern)
                return false;
        }
        return true;
    };

    for (size_t i = 0; i < size; i++) {
        if (check((char*)(base + i), pattern, mask))
            return base + i;
    }
    return 0;
}

uintptr_t PatternScanImage(uintptr_t base, const char* pattern, const char* mask) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    auto sections = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto& sec = sections[i];

        if (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uintptr_t match = PatternScan(base + sec.VirtualAddress, sec.Misc.VirtualSize, pattern, mask); 
            if (match) return match;
        }
    }
    return 0;
}