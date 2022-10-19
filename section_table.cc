#include "memory_loader.h"
void MemoryLoader::PrintRelocTable() {
    printf("------------PrintRelocTable---------------\n");

    switch (bit) {
    case BIT_64: {
        UINT64 reloc_rva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        UINT64 reloc_foa = Rva2Foa64(reloc_rva);
        printf("reloc foa:%I64X\n", reloc_foa);
        ifs.seekg(reloc_foa, std::ios::beg);

        IMAGE_BASE_RELOCATION reloc_table;
        // ifs.read((char *)&reloc_table, sizeof(IMAGE_BASE_RELOCATION));
        UINT64 offset = reloc_foa;
        do {
            /* code */
            ifs.seekg(offset, std::ios::beg);
            ifs.read((char *)&reloc_table, sizeof(IMAGE_BASE_RELOCATION));
            UINT16 addr;
            UINT64 addr_rva;
            UINT64 addr_foa;
            UINT64 change_addr;
            printf("offset:%I64X\trva:%X\tsize:%d\n", offset, reloc_table.VirtualAddress, reloc_table.SizeOfBlock);
            printf("\n");
            // printf("read file offset\tflag\treloc offset\taddr_rva\taddr_foa\tchange_addr\n");
            //
            // reloc_foa 是重定位表的foa
            // addr_offset 是读取每一项重定位项的偏移
            // addr >> 12 & 0x000F 获取标志位
            // addr & 0x0FFF 获取相对偏移，需要和重定位表的rva相加，转换成foa，在文件中定位
            // addr_rva是每个项的rva
            // addr_foa是每个项的foa
            // change_addr是addr_foa处对应的内容，载入内存的时候需要对其修改
            for (UINT64 addr_offset = 8; addr_offset < reloc_table.SizeOfBlock; addr_offset += 2) {
                ifs.seekg(offset + addr_offset, std::ios::beg);
                ifs.read((char *)&addr, 2);
                if (addr == 0) {
                    continue;
                }
                addr_rva = (addr & 0x0FFF) + reloc_table.VirtualAddress;
                addr_foa = Rva2Foa64(addr_rva);
                ifs.seekg(addr_foa, std::ios::beg);
                ifs.read((char *)&change_addr, sizeof(UINT64));
                printf("read file offset:%I64X\tflag:%x\treloc offset:%x\taddr_rva:%I64X", addr_offset, addr >> 12 & 0x000F, addr & 0x0FFF, addr_rva);
                printf("\taddr_foa:%I64X\tchange_addr%I64X\n", addr_foa, change_addr);
            }
            printf("\n");
            offset += reloc_table.SizeOfBlock;

        } while (reloc_table.VirtualAddress != 0 && reloc_table.SizeOfBlock != 0);

        // for (; reloc_table.)
        break;
    }
    case BIT_32: {
        UINT reloc_rva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        UINT reloc_foa = Rva2Foa(reloc_rva);
        printf("reloc foa:%X\n", reloc_foa);
        ifs.seekg(reloc_foa, std::ios::beg);

        IMAGE_BASE_RELOCATION reloc_table;
        // ifs.read((char *)&reloc_table, sizeof(IMAGE_BASE_RELOCATION));
        UINT offset = reloc_foa;
        do {
            /* code */
            ifs.seekg(offset, std::ios::beg);
            ifs.read((char *)&reloc_table, sizeof(IMAGE_BASE_RELOCATION));
            UINT16 addr;
            UINT addr_rva;
            UINT addr_foa;
            UINT change_addr;
            printf("offset:%X\trva:%X\tsize:%d\n", offset, reloc_table.VirtualAddress, reloc_table.SizeOfBlock);
            printf("\n");
            // printf("\t\t\t\t\t\n");
            for (UINT addr_offset = 8; addr_offset < reloc_table.SizeOfBlock; addr_offset += 2) {
                ifs.seekg(offset + addr_offset, std::ios::beg);
                ifs.read((char *)&addr, 2);
                if (addr == 0) {
                    continue;
                }
                addr_rva = (addr & 0x0FFF) + reloc_table.VirtualAddress;
                addr_foa = Rva2Foa(addr_rva);
                ifs.seekg(addr_foa, std::ios::beg);
                ifs.read((char *)&change_addr, sizeof(UINT));
                printf("read file offset:%X\tflag:%x\treloc offset:%x\taddr_rva:%X", addr_offset, addr >> 12 & 0x000F, addr & 0x0FFF, addr_rva);
                printf("\taddr_foa:%X\tchange_addr:%X\n", addr_foa, change_addr);
            }
            printf("\n");
            offset += reloc_table.SizeOfBlock;

        } while (reloc_table.VirtualAddress != 0 && reloc_table.SizeOfBlock != 0);

        break;
    }
    default:
        break;
    }
    printf("------------PrintRelocTable---------------\n\n\n");
}
void MemoryLoader::PrintImportTable() {
    printf("------------PrintImportTable---------------\n");
    switch (bit) {
    case BIT_64: {
        UINT64 table_rva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        UINT64 table_foa = Rva2Foa64(table_rva);
        UINT64 offset = table_foa;

        ifs.seekg(offset, std::ios::beg);
        // printf("%I64X\n", table_foa);
        UINT64 OriginFirstChunkFoa, FirstChunkFoa;

        UINT64 NameFoa;
        CHAR name[256];
        CHAR func_name_array[256];
        IMAGE_IMPORT_DESCRIPTOR table;
        IMAGE_THUNK_DATA64 int_thunk;
        IMAGE_IMPORT_BY_NAME func_name;
        UINT64 func_foa;
        int j;
        // 通过ntHeaders64.OptionalHeader.DataDirectory[1].Size 计算一共有几项导入表
        for (int i = 0; i < ((ntHeaders64.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1); i++) {
            // 跳到每项导入表
            ifs.seekg(offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i, std::ios::beg);
            ifs.read((char *)&table, sizeof(IMAGE_IMPORT_DESCRIPTOR));
            NameFoa = Rva2Foa64(table.Name);
            ifs.seekg(NameFoa);
            j = 0;
            // 解析导入的dll名字
            do {
                ifs.read(name + j, 1);
                j++;
            } while (name[j - 1] != '\0');
            printf("Name -> %s\n", name);

            // 获取当前导入表的INT的foa
            OriginFirstChunkFoa = Rva2Foa64(table.OriginalFirstThunk);
            // 获取当前导入表的IAT的foa
            FirstChunkFoa = Rva2Foa64(table.FirstThunk);
            printf("OriginFirstChunkFoa:%I64X\tFirstChunkRva:%I32X\tFirstChunkFoa:%I64X\n", OriginFirstChunkFoa, table.FirstThunk, FirstChunkFoa);
            ifs.seekg(OriginFirstChunkFoa, std::ios::beg);
            int cnt = 0;
            int m;
            do {
                // 读取INT表，并遍历INT表的每一项
                ifs.seekg(OriginFirstChunkFoa + cnt * sizeof(IMAGE_THUNK_DATA64), std::ios::beg);
                ifs.read((char *)&int_thunk, sizeof(IMAGE_THUNK_DATA64));
                // IMAGE_THUNK_DATA32
                if (int_thunk.u1.AddressOfData != 0) {
                    // 如果最高位为0则进入if内，此时的值为指向IMAGE_IMPORT_BY_NAME的rva
                    if (!IMAGE_SNAP_BY_ORDINAL64(int_thunk.u1.AddressOfData)) {
                        func_foa = Rva2Foa64(int_thunk.u1.AddressOfData);

                        ifs.seekg(func_foa, std::ios::beg);
                        ifs.read((char *)&func_name, sizeof(IMAGE_IMPORT_BY_NAME));
                        m = 0;
                        // 读取函数名
                        ifs.seekg(func_foa + sizeof(WORD), std::ios::beg);
                        do {
                            ifs.read(func_name_array + m, 1);
                            m++;
                        } while (func_name_array[m - 1] != '\0');
                        printf("\tfunc foa:%I64X\tfunc hint:%x\tfunc name:%s\tfunc rva:%I64X\n", func_foa, func_name.Hint, func_name_array, int_thunk.u1.AddressOfData);
                    } else {
                        // 如果为1则去掉最高位后是函数的序号
                        printf("func ord:%I64d\n", int_thunk.u1.AddressOfData - IMAGE_ORDINAL_FLAG64);
                    }
                    memset(func_name_array, 0, 256);
                }
                cnt++;
            } while (int_thunk.u1.AddressOfData != 0);

            // printf("%X\n", table.Name);
            memset(name, 0, 256);
        }

        break;
    }
    case BIT_32: {
        UINT table_rva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        UINT table_foa = Rva2Foa(table_rva);
        UINT offset = table_foa;

        ifs.seekg(offset, std::ios::beg);
        printf("%I32X\n", table_foa);
        UINT OriginFirstChunkFoa, FirstChunkFoa;

        UINT NameFoa;
        CHAR name[256];
        CHAR func_name_array[256];
        IMAGE_IMPORT_DESCRIPTOR table;
        IMAGE_THUNK_DATA32 int_thunk;
        IMAGE_IMPORT_BY_NAME func_name;
        UINT func_foa;
        int j;
        // 通过ntHeaders64.OptionalHeader.DataDirectory[1].Size 计算一共有几项导入表
        for (int i = 0; i < ((ntHeaders32.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1); i++) {
            // 跳到每项导入表
            ifs.seekg(offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i, std::ios::beg);
            ifs.read((char *)&table, sizeof(IMAGE_IMPORT_DESCRIPTOR));
            NameFoa = Rva2Foa(table.Name);
            ifs.seekg(NameFoa);
            j = 0;
            // 解析导入的dll名字
            do {
                ifs.read(name + j, 1);
                j++;
            } while (name[j - 1] != '\0');
            printf("Name -> %s\n", name);

            // 获取当前导入表的INT的foa
            OriginFirstChunkFoa = Rva2Foa(table.OriginalFirstThunk);
            // 获取当前导入表的IAT的foa
            FirstChunkFoa = Rva2Foa(table.FirstThunk);
            printf("OriginFirstChunkFoa:%I32X\tFirstChunkRva:%I32X\tFirstChunkFoa:%I32X\n", OriginFirstChunkFoa, table.FirstThunk, FirstChunkFoa);
            ifs.seekg(OriginFirstChunkFoa, std::ios::beg);
            int cnt = 0;
            int m;
            do {
                // 读取INT表，并遍历INT表的每一项
                ifs.seekg(OriginFirstChunkFoa + cnt * sizeof(IMAGE_THUNK_DATA32), std::ios::beg);
                ifs.read((char *)&int_thunk, sizeof(IMAGE_THUNK_DATA32));
                // IMAGE_THUNK_DATA32
                if (int_thunk.u1.AddressOfData != 0) {
                    // 如果最高位为0则进入if内，此时的值为指向IMAGE_IMPORT_BY_NAME的rva
                    if (!IMAGE_SNAP_BY_ORDINAL64(int_thunk.u1.AddressOfData)) {
                        func_foa = Rva2Foa(int_thunk.u1.AddressOfData);

                        ifs.seekg(func_foa, std::ios::beg);
                        ifs.read((char *)&func_name, sizeof(IMAGE_IMPORT_BY_NAME));
                        m = 0;
                        // 读取函数名
                        ifs.seekg(func_foa + sizeof(WORD), std::ios::beg);
                        do {
                            ifs.read(func_name_array + m, 1);
                            m++;
                        } while (func_name_array[m - 1] != '\0');
                        printf("\tfunc foa:%I32X\tfunc hint:%x\tfunc name:%s\tfunc rva:%I32X\n", func_foa, func_name.Hint, func_name_array, int_thunk.u1.AddressOfData);
                    } else {
                        // 如果为1则去掉最高位后是函数的序号
                        printf("func ord:%I32d\n", int_thunk.u1.AddressOfData - IMAGE_ORDINAL_FLAG32);
                    }
                    memset(func_name_array, 0, 256);
                }
                cnt++;
            } while (int_thunk.u1.AddressOfData != 0);

            // printf("%X\n", table.Name);
            memset(name, 0, 256);
        }

        break;
    }
    default:
        break;
    }
    printf("------------PrintImportTable---------------\n\n\n");
}
void MemoryLoader::PrintExportTable() {
    printf("------------PrintExportTable---------------\n");

    switch (bit) {
    case BIT_64: {
        UINT64 table_rva = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        // if (table_rva = 0) {
        //     break;
        // }
        UINT64 table_foa = Rva2Foa64(table_rva);
        IMAGE_EXPORT_DIRECTORY export_table;
        UINT64 funcs_foa;
        UINT64 names_foa;
        UINT64 name_ord_foa;
        DWORD func_rva;
        DWORD func_foa;
        WORD name_ord;
        CHAR func_name[256];
        DWORD func_name_rva;
        UINT64 func_name_foa;
        printf("table rva:%I64X\ttable foa:%I64X\n", table_rva, table_foa);
        ifs.seekg(table_foa, std::ios::beg);
        ifs.read((char *)&export_table, sizeof(IMAGE_EXPORT_DIRECTORY));
        // std::cout << export_table.Name << "\t" << export_table.AddressOfFunctions << std::endl;
        UINT64 dll_name_foa = Rva2Foa64(export_table.Name);
        CHAR dll_name[256];
        ifs.seekg(dll_name_foa, std::ios::beg);
        int i = 0;
        int j = 0;
        do {
            ifs.read(dll_name + i, 1);
            i++;
        } while (dll_name[i - 1] != '\0');
        std::cout << dll_name << std::endl;
        funcs_foa = Rva2Foa64(export_table.AddressOfFunctions);
        names_foa = Rva2Foa64(export_table.AddressOfNames);
        name_ord_foa = Rva2Foa64(export_table.AddressOfNameOrdinals);
        printf("funcs_foa:%I64X\tnames_foa:%I64X\tname_ord_foa:%I64X\n", funcs_foa, names_foa, name_ord_foa);
        printf("rva:%I64X\t%d\n", export_table.AddressOfFunctions, export_table.NumberOfNames);
        for (i = 0; i < export_table.NumberOfNames; i++) {
            ifs.seekg(name_ord_foa + i * sizeof(WORD), std::ios::beg);
            ifs.read((char *)&name_ord, sizeof(WORD));
            ifs.seekg(funcs_foa + name_ord * 4, std::ios::beg);
            ifs.read((char *)&func_rva, sizeof(DWORD));
            func_foa = Rva2Foa64(func_rva);
            ifs.seekg(names_foa + sizeof(DWORD) * i, std::ios::beg);
            ifs.read((char *)&func_name_rva, sizeof(DWORD));
            func_name_foa = Rva2Foa64(func_name_rva);
            j = 0;
            do {
                ifs.seekg(func_name_foa + j, std::ios::beg);
                ifs.read(func_name + j, 1);
                j++;
            } while (func_name[j - 1] != 0);

            std::cout << "name ord:" << name_ord << "\tfunc foa:" << func_foa << "\tfunc rva:" << func_rva << "\tfunc name:" << func_name << std::endl;

            memset(func_name, 0, 256);
        }
        break;
    }
    case BIT_32: {
        UINT table_rva = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        // if (table_rva = 0) {
        //     break;
        // }
        UINT table_foa = Rva2Foa(table_rva);
        IMAGE_EXPORT_DIRECTORY export_table;
        UINT funcs_foa;
        UINT names_foa;
        UINT name_ord_foa;
        DWORD func_rva;
        DWORD func_foa;
        WORD name_ord;
        CHAR func_name[256];
        DWORD func_name_rva;
        UINT func_name_foa;
        printf("table rva:%I32X\ttable foa:%I32X\n", table_rva, table_foa);
        ifs.seekg(table_foa, std::ios::beg);
        ifs.read((char *)&export_table, sizeof(IMAGE_EXPORT_DIRECTORY));
        // std::cout << export_table.Name << "\t" << export_table.AddressOfFunctions << std::endl;
        UINT dll_name_foa = Rva2Foa(export_table.Name);
        CHAR dll_name[256];
        ifs.seekg(dll_name_foa, std::ios::beg);
        int i = 0;
        int j = 0;
        do {
            ifs.read(dll_name + i, 1);
            i++;
        } while (dll_name[i - 1] != '\0');
        std::cout << dll_name << std::endl;
        funcs_foa = Rva2Foa(export_table.AddressOfFunctions);
        names_foa = Rva2Foa(export_table.AddressOfNames);
        name_ord_foa = Rva2Foa(export_table.AddressOfNameOrdinals);
        printf("funcs_foa:%I32X\tnames_foa:%I32X\tname_ord_foa:%I32X\n", funcs_foa, names_foa, name_ord_foa);
        printf("rva:%I32X\t%d\n", export_table.AddressOfFunctions, export_table.NumberOfNames);
        for (i = 0; i < export_table.NumberOfNames; i++) {
            ifs.seekg(name_ord_foa + i * sizeof(WORD), std::ios::beg);
            ifs.read((char *)&name_ord, sizeof(WORD));
            ifs.seekg(funcs_foa + name_ord * 4, std::ios::beg);
            ifs.read((char *)&func_rva, sizeof(DWORD));
            func_foa = Rva2Foa(func_rva);
            ifs.seekg(names_foa + sizeof(DWORD) * i, std::ios::beg);
            ifs.read((char *)&func_name_rva, sizeof(DWORD));
            func_name_foa = Rva2Foa(func_name_rva);
            j = 0;
            do {
                ifs.seekg(func_name_foa + j, std::ios::beg);
                ifs.read(func_name + j, 1);
                j++;
            } while (func_name[j - 1] != 0);

            std::cout << "name ord:" << name_ord << "\tfunc foa:" << func_foa << "\tfunc rva:" << func_rva << "\tfunc name:" << func_name << std::endl;

            memset(func_name, 0, 256);
        }
        break;
    }
    default:
        break;
    }
    printf("------------PrintExportTable---------------\n\n\n");
}

void MemoryLoader::RebaseRelocTable64(UINT64 newbaseaddr) {
}
void MemoryLoader::RebaseRelocTable(UINT newbaseaddr) {
}