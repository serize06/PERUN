import struct
import os

def generate_dummy_pe(filepath):
    # DOS Header
    # e_magic: 'MZ' (0x5a4d)
    # e_lfanew: 0x40 (offset to NT headers)
    dos_header = struct.pack(
        '<H' + 'H'*13 + 'H'*4 + 'H'*2 + 'H'*10 + 'i',
        0x5A4D, # e_magic
        0x0090, 0x0003, 0x0000, 0x0004, 0x0000, 0xFFFF, 0x0000,
        0x00B8, 0x0000, 0x0000, 0x0000, 0x0040, 0x0000, # 13 items total from e_cblp to e_ovno
        0, 0, 0, 0, # e_res
        0, 0,       # e_oemid, e_oeminfo
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, # e_res2
        0x40        # e_lfanew
    )
    
    # NT Header Signature: 'PE\0\0' (0x00004550)
    nt_signature = struct.pack('<I', 0x00004550)
    
    # File Header:
    # Machine: AMD64 (0x8664)
    # NumberOfSections: 3
    # SizeOfOptionalHeader: 240 (0xF0)
    # Characteristics: 0x0022 (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    file_header = struct.pack(
        '<HHIIIHH',
        0x8664, # Machine (AMD64)
        3,      # NumberOfSections (text, data, reloc)
        0x65F0EF00, # TimeDateStamp (dummy value)
        0,      # PointerToSymbolTable
        0,      # NumberOfSymbols
        240,    # SizeOfOptionalHeader
        0x0022  # Characteristics
    )
    
    # Optional Header (PE32+):
    # Magic: 0x020B (PE32+)
    # AddressOfEntryPoint: 0x1000
    # ImageBase: 0x140000000 (64-bit)
    # SectionAlignment: 0x1000
    # FileAlignment: 0x200
    # SizeOfImage: 0x4000
    # SizeOfHeaders: 0x200
    # NumberOfRvaAndSizes: 16
    optional_header_base = struct.pack(
        '<HBBIIIIIQIIHHHHHHIIIIHHQQQQII',
        0x020B,     # Magic: 0x020B (PE32+)
        14, 0,      # MajorLinkerVersion, MinorLinkerVersion
        0x200,      # SizeOfCode
        0x400,      # SizeOfInitializedData (data=0x200, reloc=0x200)
        0,          # SizeOfUninitializedData
        0x1000,     # AddressOfEntryPoint (RVA)
        0x1000,     # BaseOfCode
        
        # Windows-Specific Fields
        0x140000000, # ImageBase (64-bit)
        0x1000,      # SectionAlignment
        0x200,       # FileAlignment
        10, 0,       # MajorOperatingSystemVersion, MinorOperatingSystemVersion
        0, 0,        # MajorImageVersion, MinorImageVersion
        10, 0,       # MajorSubsystemVersion, MinorSubsystemVersion
        0,           # Win32VersionValue
        0x4000,      # SizeOfImage
        0x200,       # SizeOfHeaders
        0,           # CheckSum
        3,           # Subsystem (IMAGE_SUBSYSTEM_WINDOWS_CUI)
        0x8160,      # DllCharacteristics (DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE)
        0x100000,    # SizeOfStackReserve
        0x1000,      # SizeOfStackCommit
        0x100000,    # SizeOfHeapReserve
        0x1000,      # SizeOfHeapCommit
        0,           # LoaderFlags
        16           # NumberOfRvaAndSizes
    )
    
    # Data Directories (16 entries, each 8 bytes)
    # Directory Index 5 is Base Relocation Table
    dirs = [[0, 0] for _ in range(16)]
    dirs[5] = [0x3000, 12] # Relocation table at RVA 0x3000, Size 12
    flat_dirs = [val for entry in dirs for val in entry]
    data_directories = struct.pack('<' + 'II'*16, *flat_dirs)
    
    # Optional Header total
    optional_header = optional_header_base + data_directories
    
    # Section 1: .text (VirtualSize=0x200, VirtualAddress=0x1000, SizeOfRawData=0x200, PointerToRawData=0x200)
    # Characteristics: 0x60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)
    sec_text = struct.pack(
        '<8s IIIIIIHHI',
        b'.text\0\0\0',
        0x200,      # VirtualSize
        0x1000,     # VirtualAddress
        0x200,      # SizeOfRawData
        0x200,      # PointerToRawData
        0, 0,       # PointerToRelocations, PointerToLinenumbers
        0, 0,       # NumberOfRelocations, NumberOfLinenumbers
        0x60000020  # Characteristics (Code, Execute, Read)
    )
    
    # Section 2: .data (VirtualSize=0x100, VirtualAddress=0x2000, SizeOfRawData=0x200, PointerToRawData=0x400)
    # Characteristics: 0xC0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
    sec_data = struct.pack(
        '<8s IIIIIIHHI',
        b'.data\0\0\0\0',
        0x100,      # VirtualSize
        0x2000,     # VirtualAddress
        0x200,      # SizeOfRawData
        0x400,      # PointerToRawData
        0, 0,       # PointerToRelocations, PointerToLinenumbers
        0, 0,       # NumberOfRelocations, NumberOfLinenumbers
        0xC0000040  # Characteristics (Data, Read, Write)
    )

    # Section 3: .reloc (VirtualSize=0x200, VirtualAddress=0x3000, SizeOfRawData=0x200, PointerToRawData=0x600)
    # Characteristics: 0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
    sec_reloc = struct.pack(
        '<8s IIIIIIHHI',
        b'.reloc\0\0',
        0x200,      # VirtualSize
        0x3000,     # VirtualAddress
        0x200,      # SizeOfRawData
        0x600,      # PointerToRawData
        0, 0,       # PointerToRelocations, PointerToLinenumbers
        0, 0,       # NumberOfRelocations, NumberOfLinenumbers
        0x42000040  # Characteristics (Data, Discardable, Read)
    )
    
    # Headers total size must align to FileAlignment (0x200)
    headers = dos_header + nt_signature + file_header + optional_header + sec_text + sec_data + sec_reloc
    # Pad headers to 0x200 bytes
    headers += b'\0' * (0x200 - len(headers))
    
    # Section data
    # .text section data (offset 0x200 to 0x400)
    # Put a 64-bit absolute address 0x140002000 at offset 0x10
    text_data = b'\x90' * 16 + struct.pack('<Q', 0x140002000) + b'\x90' * (512 - 16 - 8)
    
    # .data section data (offset 0x400 to 0x600)
    data_data = b'Hello from PERUN mock PE!' + b'\0' * (512 - len('Hello from PERUN mock PE!'))

    # .reloc section data (offset 0x600 to 0x800)
    # 1 relocation block:
    # Page RVA: 0x1000
    # BlockSize: 12
    # Entries: 0xA010 (DIR64 at offset 0x10), 0x0000 (ABSOLUTE padding)
    reloc_data = struct.pack('<IIHH', 0x1000, 12, 0xA010, 0x0000)
    reloc_data += b'\0' * (512 - len(reloc_data))
    
    with open(filepath, 'wb') as f:
        f.write(headers)
        f.write(text_data)
        f.write(data_data)
        f.write(reloc_data)
        
    print(f"Successfully generated dummy PE at {filepath}")

if __name__ == '__main__':
    os.makedirs('/home/serize/PERUN/tests', exist_ok=True)
    generate_dummy_pe('/home/serize/PERUN/tests/dummy.exe')
