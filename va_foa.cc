#include "memory_loader.h"

UINT MemoryLoader::Va2Foa(UINT va) {
    UINT rva = va - ntHeaders32.OptionalHeader.ImageBase;
    printf("rva:%X\n", rva);
    UINT PeEndAddr = (UINT)dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    printf("pe end addr:%X\n", PeEndAddr);
    if (rva < PeEndAddr) {
        // printf("foa:%X\n", rva);
        return rva;
    } else {
        int i;
        UINT SizeInMem;
        for (i = 0; i < ntHeaders32.FileHeader.NumberOfSections; i++) {
            SizeInMem = ceil((double)max((UINT)sectionAddrArr[i]->Misc.VirtualSize, (UINT)sectionAddrArr[i]->SizeOfRawData) / (double)ntHeaders32.OptionalHeader.SectionAlignment) * ntHeaders32.OptionalHeader.SectionAlignment;

            if (rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem)) {
                printf("find:%X in %s\n", rva, sectionAddrArr[i]->Name);
                break;
            }
        }
        if (i >= ntHeaders32.FileHeader.NumberOfSections && !(rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem))) {
            //未找到
            printf("没有找到匹配的节\n");
            return -1;
        } else {
            //计算差值= RVA - 节.VirtualAddress
            UINT offset = rva - sectionAddrArr[i]->VirtualAddress;
            // FOA = 节.PointerToRawData + 差值
            UINT foa = sectionAddrArr[i]->PointerToRawData + offset;
            // printf("foa:%IX\n", foa);
            return foa;
        }
    }
}

// Virtual address 转 Foa原理：
//
UINT64 MemoryLoader::Va2Foa64(UINT64 va) {
    UINT64 rva = va - ntHeaders64.OptionalHeader.ImageBase;
    printf("rva:%I64X\n", rva);
    UINT64 PeEndAddr = (UINT64)dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    printf("pe end addr:%I64X\n", PeEndAddr);
    if (rva < PeEndAddr) {
        // printf("foa:%X\n", rva);
        return rva;
    } else {
        int i;
        UINT64 SizeInMem;
        for (i = 0; i < ntHeaders64.FileHeader.NumberOfSections; i++) {
            SizeInMem = ceil((double)max((UINT64)sectionAddrArr[i]->Misc.VirtualSize, (UINT64)sectionAddrArr[i]->SizeOfRawData) / (double)ntHeaders64.OptionalHeader.SectionAlignment) * ntHeaders64.OptionalHeader.SectionAlignment;

            if (rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem)) {
                printf("find:%I64X in %s\n", rva, sectionAddrArr[i]->Name);
                break;
            }
        }
        if (i >= ntHeaders64.FileHeader.NumberOfSections && !(rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem))) {
            //未找到
            printf("没有找到匹配的节\n");
            return -1;
        } else {
            //计算差值= RVA - 节.VirtualAddress
            UINT64 offset = rva - sectionAddrArr[i]->VirtualAddress;
            // FOA = 节.PointerToRawData + 差值
            UINT64 foa = sectionAddrArr[i]->PointerToRawData + offset;
            // printf("foa:%IX\n", foa);
            return foa;
        }
    }
}

UINT64 MemoryLoader::Rva2Foa64(UINT64 rva) {
    UINT64 PeEndAddr = (UINT64)dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    if (rva < PeEndAddr) {
        // printf("foa:%X\n", rva);
        printf("pe end addr:%I64X\n", PeEndAddr);

        return rva;
    } else {
        int i;
        UINT64 SizeInMem;
        for (i = 0; i < ntHeaders64.FileHeader.NumberOfSections; i++) {
            SizeInMem = ceil((double)max((UINT64)sectionAddrArr[i]->Misc.VirtualSize, (UINT64)sectionAddrArr[i]->SizeOfRawData) / (double)ntHeaders64.OptionalHeader.SectionAlignment) * ntHeaders64.OptionalHeader.SectionAlignment;

            if (rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem)) {
                // printf("find:%I64X in %s\n", rva, sectionAddrArr[i]->Name);
                break;
            }
        }
        if (i >= ntHeaders64.FileHeader.NumberOfSections && !(rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem))) {
            //未找到
            printf("没有找到匹配的节\n");
            return -1;
        } else {
            //计算差值= RVA - 节.VirtualAddress
            UINT64 offset = rva - sectionAddrArr[i]->VirtualAddress;
            // FOA = 节.PointerToRawData + 差值
            UINT64 foa = sectionAddrArr[i]->PointerToRawData + offset;
            // printf("foa:%IX\n", foa);
            return foa;
        }
    }
}

UINT MemoryLoader::Rva2Foa(UINT rva) {
    UINT PeEndAddr = (UINT)dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
    if (rva < PeEndAddr) {
        // printf("foa:%X\n", rva);
        printf("pe end addr:%X\n", PeEndAddr);

        return rva;
    } else {
        int i;
        UINT SizeInMem;
        for (i = 0; i < ntHeaders32.FileHeader.NumberOfSections; i++) {
            SizeInMem = ceil((double)max((UINT)sectionAddrArr[i]->Misc.VirtualSize, (UINT)sectionAddrArr[i]->SizeOfRawData) / (double)ntHeaders32.OptionalHeader.SectionAlignment) * ntHeaders32.OptionalHeader.SectionAlignment;

            if (rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem)) {
                // printf("find:%I64X in %s\n", rva, sectionAddrArr[i]->Name);
                break;
            }
        }
        if (i >= ntHeaders32.FileHeader.NumberOfSections && !(rva >= sectionAddrArr[i]->VirtualAddress && rva < (sectionAddrArr[i]->VirtualAddress + SizeInMem))) {
            //未找到
            printf("没有找到匹配的节\n");
            return -1;
        } else {
            //计算差值= RVA - 节.VirtualAddress
            UINT offset = rva - sectionAddrArr[i]->VirtualAddress;
            // FOA = 节.PointerToRawData + 差值
            UINT foa = sectionAddrArr[i]->PointerToRawData + offset;
            // printf("foa:%IX\n", foa);
            return foa;
        }
    }
}
UINT64 MemoryLoader::Foa2Rva64(UINT64 foa) {
    return -1;
}
UINT MemoryLoader::Foa2Rva(UINT foa) {
    return -1;
}