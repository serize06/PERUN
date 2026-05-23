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
        4,      # NumberOfSections (text, data, reloc, idata)
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
        0x600,      # SizeOfInitializedData (data=0x200, reloc=0x200, idata=0x200)
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
        0x5000,      # SizeOfImage
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
    # Directory Index 1 is Import Directory
    # Directory Index 5 is Base Relocation Table
    # Directory Index 12 is Import Address Table
    dirs = [[0, 0] for _ in range(16)]
    dirs[1] = [0x4000, 60]  # Import directory at RVA 0x4000, Size 60 (3 entries)
    dirs[5] = [0x3000, 12]  # Relocation table at RVA 0x3000, Size 12
    dirs[12] = [0x4060, 32] # IAT at RVA 0x4060, Size 32 (16 bytes for kernel32 IAT, 16 for msvcrt IAT)
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

    # Section 4: .idata (VirtualSize=0x200, VirtualAddress=0x4000, SizeOfRawData=0x200, PointerToRawData=0x800)
    # Characteristics: 0xC0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
    sec_idata = struct.pack(
        '<8s IIIIIIHHI',
        b'.idata\0\0',
        0x200,      # VirtualSize
        0x4000,     # VirtualAddress
        0x200,      # SizeOfRawData
        0x800,      # PointerToRawData
        0, 0,       # PointerToRelocations, PointerToLinenumbers
        0, 0,       # NumberOfRelocations, NumberOfLinenumbers
        0xC0000040  # Characteristics (Data, Read, Write)
    )
    
    # Headers total size must align to FileAlignment (0x200)
    headers = dos_header + nt_signature + file_header + optional_header + sec_text + sec_data + sec_reloc + sec_idata
    # Pad headers to 0x200 bytes
    headers += b'\0' * (0x200 - len(headers))
    
    # Section data
    # .text section data (offset 0x200 to 0x400)
    # RVA 0x1000. Contains code that executes ExitProcess(42) and retains relocation check at offset 0x10.
    code = (
        b'\xeb\x16' +                # jmp to offset 0x18 (2 bytes)
        b'\x90' * 14 +               # padding to offset 0x10 (14 bytes)
        struct.pack('<Q', 0x140002000) +  # offset 0x10: relocated address for reloc test (8 bytes)
        # offset 0x18 (RVA 0x1018):
        b'\x48\x83\xec\x28' +        # sub rsp, 40
        b'\x48\x8d\x0d\xdd\x0f\x00\x00' +  # lea rcx, [rip + 0xfdd] -> 0x2000 (format string)
        b'\x48\x8d\x15\xf6\x0f\x00\x00' +  # lea rdx, [rip + 0xff6] -> 0x2020 (arg string)
        b'\x48\x8b\x05\x4f\x30\x00\x00' +  # mov rax, [rip + 0x304f] -> 0x4080 (printf IAT)
        b'\xff\xd0' +                # call rax
        b'\x48\xc7\xc1\x2a\x00\x00\x00' +  # mov rcx, 42
        b'\x48\x8b\x05\x1f\x30\x00\x00' +  # mov rax, [rip + 0x301f] -> 0x4060 (ExitProcess IAT)
        b'\xff\xd0' +                # call rax
        b'\x48\x83\xc4\x28' +        # add rsp, 40
        b'\xc3'                      # ret
    )
    text_data = code + b'\x90' * (512 - len(code))
    
    # .data section data (offset 0x400 to 0x600)
    # RVA 0x2000: format string, RVA 0x2020: argument string
    fmt_str = b'PERUN Loader: %s\n\0'
    arg_str = b'Execution Successful!\0'
    data_data = fmt_str + b'\0' * (32 - len(fmt_str)) + arg_str + b'\0' * (512 - 32 - len(arg_str))

    # .reloc section data (offset 0x600 to 0x800)
    # 1 relocation block:
    # Page RVA: 0x1000
    # BlockSize: 12
    # Entries: 0xA010 (DIR64 at offset 0x10), 0x0000 (ABSOLUTE padding)
    reloc_data = struct.pack('<IIHH', 0x1000, 12, 0xA010, 0x0000)
    reloc_data += b'\0' * (512 - len(reloc_data))

    # .idata section data (offset 0x800 to 0xa00)
    # Layout:
    # 0x00: IDT Entry 1 (kernel32.dll)
    #   - OriginalFirstThunk (ILT RVA): 0x4050
    #   - TimeDateStamp: 0
    #   - ForwarderChain: 0
    #   - Name RVA: 0x4090
    #   - FirstThunk (IAT RVA): 0x4060
    # 0x14: IDT Entry 2 (msvcrt.dll)
    #   - OriginalFirstThunk (ILT RVA): 0x4070
    #   - TimeDateStamp: 0
    #   - ForwarderChain: 0
    #   - Name RVA: 0x40A0
    #   - FirstThunk (IAT RVA): 0x4080
    # 0x28: IDT Entry 3 (NULL)
    # 0x3C: Padding/align to 0x50 (20 bytes padding)
    # 0x50: ILT for kernel32 (ExitProcess IMAGE_IMPORT_BY_NAME RVA: 0x40B0, NULL) -> 16 bytes (ends at 0x4060)
    # 0x60: IAT for kernel32 (ExitProcess IMAGE_IMPORT_BY_NAME RVA: 0x40B0, NULL) -> 16 bytes (ends at 0x4070)
    # 0x70: ILT for msvcrt (printf IMAGE_IMPORT_BY_NAME RVA: 0x40C0, NULL) -> 16 bytes (ends at 0x4080)
    # 0x80: IAT for msvcrt (printf IMAGE_IMPORT_BY_NAME RVA: 0x40C0, NULL) -> 16 bytes (ends at 0x4090)
    # 0x90: Name string: "kernel32.dll\0" (ends at 0x409D) -> pad to 0x40A0
    # 0xA0: Name string: "msvcrt.dll\0" (ends at 0x40AB) -> pad to 0x40B0
    # 0xB0: IMAGE_IMPORT_BY_NAME for ExitProcess (Hint: 0, Name: "ExitProcess\0") (ends at 0x40BC) -> pad to 0x40C0
    # 0xC0: IMAGE_IMPORT_BY_NAME for printf (Hint: 0, Name: "printf\0") (ends at 0x40C9) -> pad to 0x40D0
    
    idt_entry1 = struct.pack('<IIIII', 0x4050, 0, 0, 0x4090, 0x4060)
    idt_entry2 = struct.pack('<IIIII', 0x4070, 0, 0, 0x40A0, 0x4080)
    idt_entry3 = struct.pack('<IIIII', 0, 0, 0, 0, 0)
    
    ilt_kernel32 = struct.pack('<QQ', 0x40B0, 0)
    iat_kernel32 = struct.pack('<QQ', 0x40B0, 0)
    
    ilt_msvcrt = struct.pack('<QQ', 0x40C0, 0)
    iat_msvcrt = struct.pack('<QQ', 0x40C0, 0)
    
    name_kernel32 = b'kernel32.dll\0'
    name_kernel32 += b'\0' * (16 - len(name_kernel32))
    
    name_msvcrt = b'msvcrt.dll\0'
    name_msvcrt += b'\0' * (16 - len(name_msvcrt))
    
    hint_exitproc = struct.pack('<H', 0) + b'ExitProcess\0'
    hint_exitproc += b'\0' * (16 - len(hint_exitproc))
    
    hint_printf = struct.pack('<H', 0) + b'printf\0'
    hint_printf += b'\0' * (16 - len(hint_printf))
    
    idata_data = (
        idt_entry1 + idt_entry2 + idt_entry3 + b'\0'*20 +
        ilt_kernel32 + iat_kernel32 +
        ilt_msvcrt + iat_msvcrt +
        name_kernel32 + name_msvcrt +
        hint_exitproc + hint_printf
    )
    idata_data += b'\0' * (512 - len(idata_data))
    
    with open(filepath, 'wb') as f:
        f.write(headers)
        f.write(text_data)
        f.write(data_data)
        f.write(reloc_data)
        f.write(idata_data)
        
    print(f"Successfully generated dummy PE at {filepath}")

if __name__ == '__main__':
    os.makedirs('/home/serize/PERUN/tests', exist_ok=True)
    generate_dummy_pe('/home/serize/PERUN/tests/dummy.exe')
