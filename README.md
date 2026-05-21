# PERUN

PERUN is a lightweight, security-hardened Windows **PE32+ (64-bit AMD64)** console executable loader and runtime library designed to run natively on Linux x86_64. 

Written strictly using the C99 standard and POSIX APIs, PERUN handles PE headers parsing, virtual memory mapping, page-level permission configuration, and base relocation patching with rigorous boundary checking to mitigate common binary parsing vulnerabilities.

---

## Key Features

### 1. Phase 1 - PE File Integrity & Structure Parsing (PE Parser)
* **DOS Header Validation:** Verifies the `MZ (0x5A4D)` magic number at the beginning of the file.
* **NT Header Validation:** Sanitizes the `e_lfanew` offset to prevent out-of-bounds memory access before validating the `PE\0\0 (0x00004550)` signature.
* **Architecture Verification:** Ensures the target machine type is `AMD64 (0x8664)` and the optional header magic is `PE32+ (0x20b)`, ensuring x64 console executable compatibility.
* **Section Bounds Checking:** Validates the layout of section headers against the raw file size to prevent malformed PE files from causing parser crashes.

### 2. Phase 2 - Virtual Memory Mapping & Page Protections (PE Loader)
* **Memory Allocation:** Maps a virtual memory block matching `SizeOfImage` via `mmap` (initially with read-write permissions: `PROT_READ | PROT_WRITE`).
* **Headers & Sections Copy:** Copies the PE headers up to `SizeOfHeaders` to the base address and maps each section to its target Relative Virtual Address (RVA).
* **BSS Padding:** Safely zero-fills any remaining virtual memory space if the `VirtualSize` of a section is greater than its `SizeOfRawData`.
* **Memory Protection (`mprotect`):** Maps section characteristics (Read/Write/Execute) to Linux page protection flags. Page-aligns the target addresses and sizes using `sysconf(_SC_PAGESIZE)` to safely invoke `mprotect`.

### 3. Phase 3 - Base Relocation Handler
* **Delta Computation:** Computes the address difference between the mapped base address (`loaded_base`) and the compiler's preferred base address (`ImageBase`).
* **Relocation Directory Parsing:** References the `IMAGE_DIRECTORY_ENTRY_BASERELOC` to parse relocation blocks (`IMAGE_BASE_RELOCATION`) page-by-page.
* **64-bit Address Patching:** Decodes 16-bit relocation entries and adds the computed delta to absolute 64-bit pointers (`IMAGE_REL_BASED_DIR64`).
* **Out-of-Bounds (OOB) Defense:** Performs strict boundary verification on block sizes, block counts, and target RVAs to prevent arbitrary memory write vulnerabilities.

### 4. Security-Hardened Design
* **Format String Protection:** Ensures error logging and console reporting functions (`printf`, `fprintf`) always use static format strings, protecting the application against format string exploits from input filenames.
* **UAF & Double-Free Mitigation:** Immediately assigns `NULL` to file streams and memory buffers after closing or freeing them (`fclose`, `free`) to prevent Use-After-Free (UAF) and Double-Free vectors.

---

## Directory Structure

```text
PERUN/
├── CMakeLists.txt              # CMake build configuration
├── README.md                   # Project documentation (This file)
├── .gitignore                  # Git ignore rules
├── include/                    # Header files
│   ├── pe_format.h            # PE32+ structure definitions and macros
│   ├── pe_parser.h            # PE parser context and function declarations
│   ├── pe_loader.h            # PE loader/mapper/relocator interface
│   └── perun.h                # Common perun context structure
├── src/                        # Source files
│   ├── main.c                 # Program entry point and flow orchestration
│   ├── pe_parser.c            # PE parser implementation (Phase 1)
│   └── pe_loader.c            # PE mapping, protection, relocation engine (Phase 2 & 3)
└── tests/                      # Testing directory
    ├── generate_dummy_pe.py   # Script to generate a dummy PE32+ binary with relocation table
    └── dummy.exe              # Synthesized target binary for loading tests
```

---

## Build Instructions

To build the project on a Linux x86_64 system, make sure `CMake` and `make` are installed:

```bash
# 1. Create and enter a build directory
mkdir build
cd build

# 2. Generate CMake build files
cmake ..

# 3. Compile the executable
make
```

Upon a successful build, the `build/perun` binary will be created.

---

## Usage

### 1. Dump PE Header & Sections Info (`--info`)
Print essential DOS/NT header metadata and the list of sections in a readable format:
```bash
./build/perun --info tests/dummy.exe
```
*Example Output:*
```text
Machine: x86_64
Format: PE32+
ImageBase: 0x140000000
EntryPoint RVA: 0x1000
Number of sections: 3

Sections:
.text    RVA=0x1000   RAW=0x200    SIZE=0x200   
.data    RVA=0x2000   RAW=0x400    SIZE=0x100   
.reloc   RVA=0x3000   RAW=0x600    SIZE=0x200   
```

### 2. Map and Apply Relocation (Default Execution Mode)
Simulate mapping, applying page-level permissions, and patching base relocation references:
```bash
./build/perun tests/dummy.exe
```
*Example Output:*
```text
Applying Relocation (Delta: 0x7a955e5ca000)...
Successfully applied relocations.
Successfully mapped and loaded PE in memory!
Allocated Base VA: 0x7a969e5ca000
SizeOfImage: 0x4000

Mapped Sections:
  .text    RVA=0x1000   -> Memory VA=0x7a969e5cb000 (Size=0x200   )
    -> [Debug] Value at .text+0x10 (relocated ptr): 0x7a969e5cc000 (expected to match .data VA)
  .data    RVA=0x2000   -> Memory VA=0x7a969e5cc000 (Size=0x100   )
  .reloc   RVA=0x3000   -> Memory VA=0x7a969e5cd000 (Size=0x200   )
```

---

## Mathematical Relocation Verification

* **Setup:** The testing script (`generate_dummy_pe.py`) injects a **64-bit absolute pointer `0x140002000`** (which corresponds to the compiler's preferred `ImageBase` `0x140000000` + `.data` section `RVA 0x2000`) into the `.text` section at offset `0x10`.
* **Delta Computation:** If the Linux OS maps the image at address `0x7a969e5ca000`, the loader computes the delta offset:
  $$\text{Delta} = 0x7a969e5ca000 - 0x140000000 = 0x7a955e5ca000$$
* **Patch Application:** The relocation engine adds this delta to the absolute pointer at `.text` offset `0x10`:
  $$\text{Patched Value} = 0x140002000 + 0x7a955e5ca000 = 0x7a969e5cc000$$
* **Verification:** The patched value (`0x7a969e5cc000`) matches the actual absolute virtual memory address where the `.data` section was mapped (`Memory VA = 0x7a969e5cc000`). This demonstrates that the loader's mapping offsets and relocation tables are patched with 100% mathematical precision.
