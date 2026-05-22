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

### 4. Phase 4 - Import Address Table (IAT) & DLL Resolver
* **Import Directory Parsing:** Navigates the `IMAGE_DIRECTORY_ENTRY_IMPORT` data directory to traverse the DLL import descriptors and lookup tables (ILT).
* **Mock Stub Engine:** Integrates native C mock stubs (e.g., `mock_ExitProcess`, `mock_printf`) to intercept and handle calls intended for Windows system libraries on Linux.
* **IAT Binding:** Patches the Import Address Table (IAT) with the actual addresses of the resolved mock functions in memory before execution.

### 5. Phase 5 - EntryPoint Execution & Calling Convention Mapping
* **ABI Calling Convention Bridge:** Interposes the Microsoft x64 calling convention (`ms_abi`) for all mock function definitions, resolving register mismatches (`RCX` vs `RDI`) between PE binary execution and Linux host execution.
* **ISO C Compliant Execution:** Transitions execution control to the mapped PE `AddressOfEntryPoint` using ISO C compliant union type casts to bypass `-Wpedantic` warnings.

### 6. Security-Hardened Design
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
Number of sections: 4

Sections:
.text    RVA=0x1000   RAW=0x200    SIZE=0x200   
.data    RVA=0x2000   RAW=0x400    SIZE=0x100   
.reloc   RVA=0x3000   RAW=0x600    SIZE=0x200   
.idata   RVA=0x4000   RAW=0x800    SIZE=0x200   
```

### 2. Map, Relocate, Resolve Imports, and Execute (Default Execution Mode)
Simulate mapping, applying base relocation, binding resolved IAT functions, and executing the entry point of the PE:
```bash
./build/perun tests/dummy.exe
```
*Example Output:*
```text
Applying Relocation (Delta: 0x7069f6244000)...
Successfully applied relocations.
Resolving Imports...
Importing from DLL: kernel32.dll
  [Function] ExitProcess -> Resolved to mock_ExitProcess (0x57a1cde8783e)
Successfully resolved all imports.
Successfully mapped and loaded PE in memory!
Allocated Base VA: 0x706b36244000
SizeOfImage: 0x5000

Mapped Sections:
  .text    RVA=0x1000   -> Memory VA=0x706b36245000 (Size=0x200   )
    -> [Debug] Value at .text+0x10 (relocated ptr): 0x706b36246000 (expected to match .data VA)
  .data    RVA=0x2000   -> Memory VA=0x706b36246000 (Size=0x100   )
  .reloc   RVA=0x3000   -> Memory VA=0x706b36247000 (Size=0x200   )
  .idata   RVA=0x4000   -> Memory VA=0x706b36248000 (Size=0x200   )
    -> [Debug] Value at .idata+0x40 (resolved IAT entry): 0x57a1cde8783e

Starting execution flow...
Executing Entry Point (VA: 0x706b36245000)...

[Mock API] ExitProcess called with code: 42
```

---

## Integration and Calling Convention Verification

### 1. Mathematical Relocation Verification
* **Setup:** The testing script (`generate_dummy_pe.py`) injects a **64-bit absolute pointer `0x140002000`** (ImageBase `0x140000000` + `.data` section RVA `0x2000`) into the `.text` section at offset `0x10`.
* **Delta Computation:** If the loader maps the image at address `0x706b36244000`, the delta offset is computed as:
  $$\text{Delta} = 0x706b36244000 - 0x140000000 = 0x7069f6244000$$
* **Patch Application:** The relocation engine adds this delta to the absolute pointer at `.text` offset `0x10`:
  $$\text{Patched Value} = 0x140002000 + 0x7069f6244000 = 0x706b36246000$$
* **Verification:** The patched value (`0x706b36246000`) matches the actual absolute virtual memory address where the `.data` section was mapped (`Memory VA = 0x706b36246000`).

### 2. ABI Calling Convention Mapping

* **Objective:** Allow C-based mock functions compiled for System V ABI (Linux x64) to receive parameters properly from Windows x64 binaries calling them.
* **Solution:** We apply `__attribute__((ms_abi))` to all mock function interfaces (e.g. `mock_ExitProcess`).
* **Execution Flow:**
  1. The entry point of `dummy.exe` executes code that sets up parameters under Microsoft x64 calling convention:
     * Sets the first parameter `rcx` to `42`.
  2. The code loads the `ExitProcess` address from the resolved IAT at `0x4040` (value `0x57a1cde8783e`) and performs a call.
  3. The control transitions to `mock_ExitProcess`. The function parses `rcx` as the exit code parameter, logs `ExitProcess called with code: 42`, and calls `exit(42)`.
  4. The program successfully exits with code `42`, proving that IAT resolution, memory protections, and execution flow are correctly mapped.
