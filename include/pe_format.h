#ifndef PE_FORMAT_H
#define PE_FORMAT_H

#include <stdint.h>

#pragma pack(push, 1)

// DOS Header (MZ)
typedef struct {
    uint16_t e_magic;    // Magic number ("MZ")
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information; e_oemid specific
    uint16_t e_res2[10]; // Reserved words
    int32_t  e_lfanew;   // File address of new exe header (offset to NT Header)
} IMAGE_DOS_HEADER;

// COFF File Header
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

// Data Directory
typedef struct {
    uint32_t VirtualAddress; // RVA
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

// Directories indices
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

// Optional Header for PE32+ (64-bit)
typedef struct {
    uint16_t Magic; // 0x20b for PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint; // RVA of entry point
    uint32_t BaseOfCode;
    
    // Windows-specific fields
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

// NT Header for PE32+ (64-bit)
typedef struct {
    uint32_t Signature; // "PE\0\0" (0x00004550)
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

// Section Header
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct {
    uint8_t  Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

// Machine types
#define IMAGE_FILE_MACHINE_I386   0x014c
#define IMAGE_FILE_MACHINE_AMD64  0x8664

// Subsystems
#define IMAGE_SUBSYSTEM_UNKNOWN                 0
#define IMAGE_SUBSYSTEM_NATIVE                  1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI             2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI             3 // Console
#define IMAGE_SUBSYSTEM_OS2_CUI                 5
#define IMAGE_SUBSYSTEM_POSIX_CUI               7
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS          8
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI          9
#define IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define IMAGE_SUBSYSTEM_EFI_ROM                 13
#define IMAGE_SUBSYSTEM_XBOX                    14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

// Section Characteristics
#define IMAGE_SCN_MEM_SHARED               0x10000000
#define IMAGE_SCN_MEM_EXECUTE              0x20000000
#define IMAGE_SCN_MEM_READ                 0x40000000
#define IMAGE_SCN_MEM_WRITE                0x80000000

// Base Relocation Header
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
} IMAGE_BASE_RELOCATION;

// Base Relocation Types
#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_DIR64                 10

#pragma pack(pop)

#endif // PE_FORMAT_H
