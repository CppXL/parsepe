
#include "memory_loader.h"

#include <sstream>
#include <fstream>
#include <time.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

MemoryLoader::~MemoryLoader() {
    ifs.close();
    // free(this->sectionAddrArr[0]);
    // free(sectionAddrArr);
    // free(DOS_STUB);
}

MemoryLoader::MemoryLoader(std::string path) {
    // 判断是文件还是目录
    DWORD attr = GetFileAttributes(path.c_str());
    // 如果路径错误就使用默认的路径

    this->path = path;
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::cout << "path:" << path.c_str() << " does not exists." << std::endl;
        std::cout << "Use default path:D:\\code\\c\\code.exe\n";
        this->path = "F:\\code\\c\\code.exe";
    }
    if (attr == FILE_ATTRIBUTE_DIRECTORY) {
        std::cout << "path " << path.c_str() << " is a directory" << std::endl;
        this->path = "D:\\code\\c\\code.exe";
    }
    std::cout << "Open file " << this->path << std::endl;
    ifs.open(this->path.c_str(), std::ios::in | std::ios::binary);
    if (!ifs) {
        std::cout << "failed open" << std::endl;
    }
}

MemoryLoader::MemoryLoader() {
    this->path = "D:\\code\\c\\helloworld.exe";
    ifs.open(path.c_str(), std::ios::in | std::ios::binary);
}

std::string MemoryLoader::GetPath() {
    return this->path;
}

void MemoryLoader::ReadDOSHeader() {
    WORD mz;
    ifs.seekg(0, std::ios::beg);
    ifs.read((char *)&mz, 2);
    // 判断是不是ms_dos兼容的
    if (mz != IMAGE_DOS_SIGNATURE) {
        std::cout << "文件头不是dos头\tpath:" << path << std::endl;
        return;
    }
    ifs.seekg(0, std::ios::beg);
    ifs.read((char *)&dosHeader, sizeof(IMAGE_DOS_HEADER));
}

void MemoryLoader::ShowDOSHeaderInfo() {
    //

    // std::cout << "offset: " << ifs.tellg() << std::endl;
    std::cout << "file header was DOS Header" << std::endl;
    std::cout << "magic number:" << std::hex << dosHeader.e_magic << std::endl;
    std::cout << "UsedBytesInTheLastPage:" << std::dec << dosHeader.e_cblp << std::endl;
    std::cout << "FileSizeInPages:" << dosHeader.e_cp << std::endl;
    std::cout << "NumberOfRelocationItems:" << dosHeader.e_crlc << std::endl;
    std::cout << "HeaderSizeInParagraphs:" << dosHeader.e_cparhdr << std::endl;
    std::cout << "MinimumExtraParagraphs:" << dosHeader.e_minalloc << std::endl;
    std::cout << "MaximumExtraParagraphs:" << dosHeader.e_maxalloc << std::endl;
    std::cout << "InitialRelativeSS:" << dosHeader.e_ss << std::endl;
    std::cout << "InitialSP:" << dosHeader.e_sp << std::endl;
    std::cout << "Checksum:" << dosHeader.e_csum << std::endl;
    std::cout << "InitialIP:" << dosHeader.e_ip << std::endl;
    std::cout << "InitialRelativeCS:" << dosHeader.e_cs << std::endl;
    std::cout << "AddressOfRelocationTable:" << dosHeader.e_lfarlc << std::endl;
    std::cout << "OverlayNumber:" << dosHeader.e_ovno << std::endl;
    for (size_t i = 0; i < 4; i++) {
        printf("\tReserved[%zd]:%d\n", i, dosHeader.e_res[i]);
    }
    std::cout << "OEMid:" << dosHeader.e_oemid << std::endl;
    std::cout << "OEMinfo:" << dosHeader.e_oeminfo << std::endl;
    for (size_t i = 0; i < 10; i++) {
        printf("\tReserved2[%zd]:%I32d\n", i, dosHeader.e_res2[i]);
    }

    std::cout << "AddressOfNewExeHeader:0x" << std::hex << dosHeader.e_lfanew << std::endl;

    int stub_size = dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
    printf("size:%zd\n", sizeof(IMAGE_DOS_HEADER));
    printf("offset:%d %d\n", dosHeader.e_lfanew, stub_size);
    DOS_STUB = (char *)malloc(stub_size);
    ifs.seekg(sizeof(IMAGE_DOS_HEADER), std::ios::beg);
    ifs.read(DOS_STUB, stub_size);
    for (int i = 0; i < stub_size; i++) {
        printf("%c", DOS_STUB[i]);
    }
    printf("\n\n\n");
}

void MemoryLoader::ShowMatchine(WORD matchine) {
    switch (matchine) {
    case IMAGE_MATCHINE::IMAGE_MACHINE_UNKNOWN:
        std::cout << "未知" << std::endl;
        break;
    case IMAGE_MATCHINE::I386:
        std::cout << "I386" << std::endl;
        break;
    case IMAGE_MATCHINE::R3000:
        std::cout << "R3000" << std::endl;
        break;
    case IMAGE_MATCHINE::R4000:
        std::cout << "R4000" << std::endl;
        break;
    case IMAGE_MATCHINE::R10000:
        std::cout << "R10000" << std::endl;
        break;
    case IMAGE_MATCHINE::WCEMIPSV2:
        std::cout << "WCEMIPSV2" << std::endl;
        break;
    case IMAGE_MATCHINE::ALPHA:
        std::cout << "ALPHA" << std::endl;
        break;
    case IMAGE_MATCHINE::SH3:
        std::cout << "SH3" << std::endl;
        break;
    case IMAGE_MATCHINE::SH3DSP:
        std::cout << "SH3DSP" << std::endl;
        break;
    case IMAGE_MATCHINE::SH3E:
        std::cout << "SH3E" << std::endl;
        break;
    case IMAGE_MATCHINE::SH4:
        std::cout << "SH4" << std::endl;
        break;
    case IMAGE_MATCHINE::SH5:
        std::cout << "SH5" << std::endl;
        break;
    case IMAGE_MATCHINE::ARM:
        std::cout << "ARM" << std::endl;
        break;
    case IMAGE_MATCHINE::THUMB:
        std::cout << "THUMB" << std::endl;
        break;

    case IMAGE_MATCHINE::AM33:
        std::cout << "AM33" << std::endl;
        break;
    case IMAGE_MATCHINE::POWERPC:
        std::cout << "POWERPC" << std::endl;
        break;
    case IMAGE_MATCHINE::POWERPCFP:
        std::cout << "POWERPCFP" << std::endl;
        break;
    case IMAGE_MATCHINE::IA64:
        std::cout << "IA64" << std::endl;
        break;
    case IMAGE_MATCHINE::MIPS16:
        std::cout << "MIPS16" << std::endl;
        break;
    case IMAGE_MATCHINE::ALPHA64:
        std::cout << "ALPHA64" << std::endl;
        break;
    case IMAGE_MATCHINE::MIPSFPU:
        std::cout << "MIPSFPU" << std::endl;
        break;
    case IMAGE_MATCHINE::MIPSFPU16:
        std::cout << "MIPSFPU16" << std::endl;
        break;
    case IMAGE_MATCHINE::TRICORE:
        std::cout << "TRICORE" << std::endl;
        break;
    case IMAGE_MATCHINE::CEF:
        std::cout << "CEF" << std::endl;
        break;
    case IMAGE_MATCHINE::EBC:
        std::cout << "EBC" << std::endl;
        break;
    case IMAGE_MATCHINE::AMD64:
        std::cout << "AMD64" << std::endl;
        break;
    case IMAGE_MATCHINE::M32R:
        std::cout << "M32R" << std::endl;
        break;
    case IMAGE_MATCHINE::CEE:
        std::cout << "CEE" << std::endl;
        break;
    default:
        std::cout << "未知错误" << std::endl;
        break;
    }
}
void MemoryLoader::ReadNTHeader() {
    std::cout << "----------------ReadNTHeader--------------\n";
    ifs.seekg(dosHeader.e_lfanew, std::ios::beg);
    DWORD signature;
    ifs.read((char *)&signature, sizeof(DWORD));
    if (signature != IMAGE_NT_SIGNATURE) {
        std::cout << "不是NT头" << std::endl;
        return;
    }
    // 是nt头 读取Signature之后，读指针指向dosHeader.e_lfanew + 4即FileHeader处，此时开始读取FileHeader
    // 通过OptionalHeader的大小判断是几位的PE
    ifs.read((char *)&fileHeader, sizeof(IMAGE_FILE_HEADER));
    WORD magic;
    ifs.read((char *)&magic, sizeof(WORD));
    std::cout << "\n\nmagic:" << std::hex << magic << std::endl;
    // 重新把读指针跳到nt头开始处
    ifs.seekg(dosHeader.e_lfanew, std::ios::beg);
    switch (magic) {
        // 64位
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC: {
        bit = BIT_64; // 64位
        std::cout << "64 位程序" << std::endl;
        // 开始解析nt头
        ifs.read((char *)&ntHeaders64, sizeof(IMAGE_NT_HEADERS64));
        break;
    }
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC: {
        std::cout << "32 位程序" << fileHeader.SizeOfOptionalHeader << std::endl
                  << path << std::endl;
        ifs.read((char *)&ntHeaders32, sizeof(IMAGE_NT_HEADERS32));
        bit = BIT_32;
        break;
    }
    case IMAGE_ROM_OPTIONAL_HDR_MAGIC: {
        std::cout << "ROM架构" << std::endl;
        break;
    }
    default:
        std::cout << "未知架构" << std::endl;
        break;
    }
    std::cout << "----------------ReadNTHeader--------------\n\n\n";
}
void MemoryLoader::ShowNTHeaderInfo() {
    // 将文件读指针朝文件结尾移动dosHeader.e_lfanew个字节
    std::cout << "----------------ShowNTHeaderInfo--------------\n";

    switch (bit) {
    case BIT_64: {
        std::cout << "运行平台:";
        this->ShowMatchine(ntHeaders64.FileHeader.Machine);
        std::cout << "Number of Sections:" << std::dec << ntHeaders64.FileHeader.NumberOfSections << std::endl;
        time_t tsp = ntHeaders64.FileHeader.TimeDateStamp;
        std::cout << "timestamp:" << tsp << "=>" << ctime(&tsp) << std::endl;
        std::cout << "PointerToSymbolTable:" << std::hex << ntHeaders64.FileHeader.PointerToSymbolTable << std::endl;
        std::cout << "BaseAddress:" << std::hex << ntHeaders64.OptionalHeader.ImageBase << std::endl;
        // Va2Foa64(0x14000C000);
        // Va2Foa64(0x14000E3A0);
        // Va2Foa64(0x14000E86A);
        // Va2Foa64(0x140011000);
        ParseSectionTable64();
        // printf("foa:%I64X\n", Va2Foa64(0x140009000));
        // printf("foa:%I64X\n", Rva2Foa64(0x110));
        // printf("foa:%I64X\n", Rva2Foa64(0x9440));
        // printf("foa:%I64X\n", Rva2Foa64(11000));
        break;
    }
    case BIT_32: {
        this->ShowMatchine(ntHeaders32.FileHeader.Machine);
        ParseSectionTable();
        // Va2Foa(0x401000);
        // Va2Foa(0x40E000);
        // Va2Foa(0x401000);
        Rva2Foa(0x1000);
        Rva2Foa(0xe000);
        break;
    }
    default:
        break;
    }
    std::cout << "----------------ShowNTHeaderInfo--------------\n\n\n";

    // IMAGE_REL_BASED_DIR64
}

void MemoryLoader::ParseSectionTable64() {
    std::cout << "AddressOfEntryPoint:" << ntHeaders64.OptionalHeader.AddressOfEntryPoint << std::endl;
    // 分配空间 存储节表
    sectionAddrArr = (IMAGE_SECTION_HEADER **)malloc(sizeof(IMAGE_SECTION_HEADER *) * ntHeaders64.FileHeader.NumberOfSections + 1);
    memset(sectionAddrArr, NULL, sizeof(IMAGE_SECTION_HEADER *) * ntHeaders64.FileHeader.NumberOfSections + 1);
    IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER) * ntHeaders64.FileHeader.NumberOfSections);
    ifs.seekg(dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64), std::ios::beg);
    ifs.read((char *)sectionHeader, sizeof(IMAGE_SECTION_HEADER) * ntHeaders64.FileHeader.NumberOfSections);
    // 遍历节表
    IMAGE_SECTION_HEADER *section;
    for (int cnt = 0; cnt < ntHeaders64.FileHeader.NumberOfSections; cnt++) {
        section = (IMAGE_SECTION_HEADER *)((char *)sectionHeader + sizeof(IMAGE_SECTION_HEADER) * cnt);
        // std::cout << "NO" << cnt + 1 << " " << section->Name << std::endl;
        sectionAddrArr[cnt] = section;
    }
    // 将最后一个元素置为NULL
    std::cout << "---------print section name--------------" << std::endl;
    sectionAddrArr[ntHeaders64.FileHeader.NumberOfSections] = NULL;
    for (int cnt = 0; sectionAddrArr[cnt] != NULL; cnt++) {
        std::cout << "NO." << cnt << " " << sectionAddrArr[cnt]->Name << std::endl;
    }
    std::cout << "---------print section name--------------" << std::endl;
}

void MemoryLoader::ParseSectionTable() {
    std::cout << "AddressOfEntryPoint:" << ntHeaders32.OptionalHeader.AddressOfEntryPoint << std::endl;
    // 分配空间 存储节表

    sectionAddrArr = (IMAGE_SECTION_HEADER **)malloc(sizeof(IMAGE_SECTION_HEADER *) * ntHeaders32.FileHeader.NumberOfSections + 1);
    memset(sectionAddrArr, NULL, sizeof(IMAGE_SECTION_HEADER *) * ntHeaders32.FileHeader.NumberOfSections + 1);
    IMAGE_SECTION_HEADER *sectionHeader = (IMAGE_SECTION_HEADER *)malloc(sizeof(IMAGE_SECTION_HEADER) * ntHeaders32.FileHeader.NumberOfSections);
    ifs.seekg(dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32), std::ios::beg);
    ifs.read((char *)sectionHeader, sizeof(IMAGE_SECTION_HEADER) * ntHeaders32.FileHeader.NumberOfSections);
    // 遍历节表
    IMAGE_SECTION_HEADER *section;
    for (int cnt = 0; cnt < ntHeaders32.FileHeader.NumberOfSections; cnt++) {
        section = (IMAGE_SECTION_HEADER *)((char *)sectionHeader + sizeof(IMAGE_SECTION_HEADER) * cnt);
        // std::cout << "NO" << cnt + 1 << " " << section->Name << std::endl;
        // std::cout << std::hex << section << std::endl;
        sectionAddrArr[cnt] = section;
    }
    // 将最后一个元素置为NULL
    std::cout << "---------print section name--------------" << std::endl;
    sectionAddrArr[ntHeaders32.FileHeader.NumberOfSections] = NULL;
    for (int cnt = 0; sectionAddrArr[cnt] != NULL; cnt++) {
        std::cout << "NO." << cnt << " " << sectionAddrArr[cnt]->Name << std::endl;
    }
    std::cout << "---------print section name--------------\n\n\n";
}

BIT MemoryLoader::GetBit() {
    return this->bit;
}