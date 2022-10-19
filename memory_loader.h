#ifndef MEM_LOADER
#define MEM_LOADER
#endif

#ifdef MEM_LOADER
#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <sstream>
#include <fstream>
#endif

// 定义各个平台对应的数字
typedef enum _IMAGE_MATCHINE {
    IMAGE_MACHINE_UNKNOWN = 0,
    I386 = 0x014c,
    R3000 = 0x0162,     // MIPS little-endian, 0x160 big-endian
    R4000 = 0x0166,     // MIPS little-endian
    R10000 = 0x0168,    // MIPS little-endian
    WCEMIPSV2 = 0x0169, // MIPS little-endian WCE v2
    ALPHA = 0x0184,     // Alpha_AXP
    SH3 = 0x01a2,       // SH3 little-endian
    SH3DSP = 0x01a3,
    SH3E = 0x01a4, // SH3E little-endian
    SH4 = 0x01a6,  // SH4 little-endian
    SH5 = 0x01a8,  // SH5
    ARM = 0x01c0,  // ARM Little-Endian
    THUMB = 0x01c2,
    AM33 = 0x01d3,
    POWERPC = 0x01F0, // IBM PowerPC Little-Endian
    POWERPCFP = 0x01f1,
    IA64 = 0x0200,      // Intel 64
    MIPS16 = 0x0266,    // MIPS
    ALPHA64 = 0x0284,   // ALPHA64
    MIPSFPU = 0x0366,   // MIPS
    MIPSFPU16 = 0x0466, // MIPS
    TRICORE = 0x0520,   // Infineon
    CEF = 0x0CEF,
    EBC = 0x0EBC,   // EFI Byte Code
    AMD64 = 0x8664, // AMD64 (K8)
    M32R = 0x9041,  // M32R little-endian
    CEE = 0xC0EE
} IMAGE_MATCHINE;

typedef enum _BIT {
    BIT_64 = 1,
    BIT_32 = 2
} BIT;

class MemoryLoader {
private:
    /* data */
    std::string path;
    std::ifstream ifs;
    BIT bit;
    DWORD fileSize;
    // DOS头兼容会有这个
    IMAGE_DOS_HEADER dosHeader;
    // 在ntHeaders里面有这个
    char *DOS_STUB;
    IMAGE_MATCHINE matchines;
    IMAGE_FILE_HEADER fileHeader;
    // 32和64位的NT头
    IMAGE_NT_HEADERS32 ntHeaders32 = {0};
    IMAGE_NT_HEADERS64 ntHeaders64 = {0};
    IMAGE_SECTION_HEADER **sectionAddrArr = nullptr;

public:
    MemoryLoader(std::string path);
    void ShowDOSHeaderInfo();
    void ReadDOSHeader();
    void ReadNTHeader();
    void ShowNTHeaderInfo();
    BIT GetBit();
    // 处理节表
    void ParseSectionTable64();
    void ParseSectionTable();
    UINT64 Va2Foa64(UINT64 va);
    UINT Va2Foa(UINT va);
    UINT64 Rva2Foa64(UINT64 rva);
    UINT Rva2Foa(UINT rva);
    UINT64 Foa2Rva64(UINT64 foa);
    UINT Foa2Rva(UINT foa);
    void PrintRelocTable();
    void RebaseRelocTable64(UINT64 newbaseaddr);
    void RebaseRelocTable(UINT newbaseaddr);
    void PrintImportTable();
    void PrintExportTable();

    MemoryLoader();
    ~MemoryLoader();
    std::string GetPath();
    BOOL LoadPE2Mem();

protected:
    void ShowMatchine(WORD matchine);
};
