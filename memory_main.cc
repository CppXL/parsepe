#include "memory_loader.h"

int main() {
    std::string path;
    std::cin >> path;
    MemoryLoader ml(path);
    ml.ReadDOSHeader();
    ml.ShowDOSHeaderInfo();
    ml.ReadNTHeader();
    switch (ml.GetBit()) {
    case BIT_64:
        ml.ParseSectionTable64();
        break;
    case BIT_32:
        ml.ParseSectionTable();
        break;
    default:
        break;
    }
    // ml.ShowNTHeaderInfo();
    // switch (ml.get_bit()) {
    // case BIT_64:
    //     /* code */
    //     ml.ParseSectionTable64();
    //     break;
    // case BIT_32:
    //     ml.ParseSectionTable();

    // default:
    //     break;
    // }
    ml.PrintRelocTable();
    ml.PrintImportTable();
    ml.PrintExportTable();
    return 0;
}