#include "pe_loader.h"
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int pe_loader_init(pe_loader_context *ctx, pe_parser_context *parser_ctx) {
    if (!ctx || !parser_ctx || !parser_ctx->nt_headers) {
        return -1;
    }
    memset(ctx, 0, sizeof(pe_loader_context));
    ctx->parser_ctx = parser_ctx;
    ctx->image_size = parser_ctx->nt_headers->OptionalHeader.SizeOfImage;
    return 0;
}

int pe_loader_map(pe_loader_context *ctx) {
    if (!ctx || !ctx->parser_ctx) {
        return -1;
    }

    pe_parser_context *parser = ctx->parser_ctx;
    
    // 1. Allocate virtual memory space in Linux process
    // We map with read-write permission initially to copy headers and section raw data.
    ctx->loaded_base = mmap(
        NULL, 
        ctx->image_size, 
        PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, 
        -1, 
        0
    );

    if (ctx->loaded_base == MAP_FAILED) {
        perror("[Error] mmap allocation failed");
        ctx->loaded_base = NULL;
        return -1;
    }

    // 2. Copy PE Headers to the base address
    uint32_t size_of_headers = parser->nt_headers->OptionalHeader.SizeOfHeaders;
    if (size_of_headers > ctx->image_size) {
        fprintf(stderr, "[Error] SizeOfHeaders (%u) exceeds SizeOfImage (%zu)\n", size_of_headers, ctx->image_size);
        munmap(ctx->loaded_base, ctx->image_size);
        ctx->loaded_base = NULL;
        return -1;
    }
    memcpy(ctx->loaded_base, parser->file_data, size_of_headers);

    // 3. Map each section to its respective RVA
    uint16_t num_sections = parser->nt_headers->FileHeader.NumberOfSections;
    for (uint16_t i = 0; i < num_sections; i++) {
        IMAGE_SECTION_HEADER *sec = &parser->section_headers[i];
        
        // RVA validity check
        if (sec->VirtualAddress + sec->Misc.VirtualSize > ctx->image_size) {
            fprintf(stderr, "[Error] Section %d exceeds image boundary\n", i);
            munmap(ctx->loaded_base, ctx->image_size);
            ctx->loaded_base = NULL;
            return -1;
        }

        void *dest = ctx->loaded_base + sec->VirtualAddress;
        
        // Copy raw data if present
        if (sec->SizeOfRawData > 0) {
            if (sec->PointerToRawData + sec->SizeOfRawData > parser->file_size) {
                fprintf(stderr, "[Error] Section %d raw data exceeds file size\n", i);
                munmap(ctx->loaded_base, ctx->image_size);
                ctx->loaded_base = NULL;
                return -1;
            }
            const void *src = parser->file_data + sec->PointerToRawData;
            memcpy(dest, src, sec->SizeOfRawData);
        }

        // BSS Zero-Fill
        // If VirtualSize > SizeOfRawData, pad the remaining space with zeroes
        if (sec->Misc.VirtualSize > sec->SizeOfRawData) {
            size_t bss_size = sec->Misc.VirtualSize - sec->SizeOfRawData;
            memset((uint8_t *)dest + sec->SizeOfRawData, 0, bss_size);
        }
    }

    return 0;
}

int pe_loader_relocate(pe_loader_context *ctx) {
    if (!ctx || !ctx->loaded_base || !ctx->parser_ctx) {
        return -1;
    }

    pe_parser_context *parser = ctx->parser_ctx;
    IMAGE_OPTIONAL_HEADER64 *opt_hdr = &parser->nt_headers->OptionalHeader;
    
    // Get relocation data directory
    IMAGE_DATA_DIRECTORY *reloc_dir = &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    // If no relocation table, check if we mapped it at the preferred base address
    if (reloc_dir->VirtualAddress == 0 || reloc_dir->Size == 0) {
        if ((uintptr_t)ctx->loaded_base != opt_hdr->ImageBase) {
            fprintf(stderr, "[Warning] Binary requires relocation, but has no relocation directory! "
                            "Loaded at %p, preferred base 0x%lx\n", (void *)ctx->loaded_base, opt_hdr->ImageBase);
            return -1;
        }
        printf("No relocation directory found, and image mapped at preferred base address.\n");
        return 0;
    }

    uintptr_t delta = (uintptr_t)ctx->loaded_base - opt_hdr->ImageBase;
    if (delta == 0) {
        printf("Relocation: Image loaded at preferred base address (0x%lx). No patching needed.\n", opt_hdr->ImageBase);
        return 0;
    }

    printf("Applying Relocation (Delta: 0x%tx)...\n", (ptrdiff_t)delta);

    // Relocation table pointer in memory
    uint8_t *reloc_base = (uint8_t *)pe_loader_rva_to_va(ctx, reloc_dir->VirtualAddress);
    if (!reloc_base) {
        fprintf(stderr, "[Error] Relocation table RVA 0x%x is out of image bounds\n", reloc_dir->VirtualAddress);
        return -1;
    }

    uint8_t *reloc_end = reloc_base + reloc_dir->Size;
    uint8_t *curr = reloc_base;

    while (curr < reloc_end) {
        // Safe boundary check for the block header
        if (curr + sizeof(IMAGE_BASE_RELOCATION) > reloc_end) {
            fprintf(stderr, "[Error] Relocation table block header is out of bounds\n");
            return -1;
        }

        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)curr;
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            fprintf(stderr, "[Error] Invalid SizeOfBlock (%u) in relocation table\n", block->SizeOfBlock);
            return -1;
        }

        if (curr + block->SizeOfBlock > reloc_end) {
            fprintf(stderr, "[Error] Relocation block exceeds table boundaries\n");
            return -1;
        }

        uint32_t page_rva = block->VirtualAddress;
        uint32_t num_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        uint16_t *entries = (uint16_t *)(curr + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t entry = entries[i];
            uint8_t type = entry >> 12;
            uint16_t offset = entry & 0x0FFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // Padding entry, ignore
                continue;
            } else if (type == IMAGE_REL_BASED_DIR64) {
                // 64-bit absolute address relocation
                uint32_t target_rva = page_rva + offset;
                
                // Safety boundary check
                if (target_rva + sizeof(uint64_t) > ctx->image_size) {
                    fprintf(stderr, "[Error] Relocation target RVA 0x%x is out of image bounds\n", target_rva);
                    return -1;
                }

                uint64_t *patch_addr = (uint64_t *)((uint8_t *)ctx->loaded_base + target_rva);
                *patch_addr += delta;
            } else {
                fprintf(stderr, "[Error] Unsupported relocation type %u\n", type);
                return -1;
            }
        }

        curr += block->SizeOfBlock;
    }

    printf("Successfully applied relocations.\n");
    return 0;
}

__attribute__((ms_abi)) static void mock_ExitProcess(uint32_t exit_code) {
    printf("[Mock API] ExitProcess called with code: %u\n", exit_code);
    exit((int)exit_code);
}

__attribute__((ms_abi)) static int mock_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("[Mock API] printf called: ");
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
}

int pe_loader_resolve_imports(pe_loader_context *ctx) {
    if (!ctx || !ctx->loaded_base || !ctx->parser_ctx) {
        return -1;
    }

    pe_parser_context *parser = ctx->parser_ctx;
    IMAGE_OPTIONAL_HEADER64 *opt_hdr = &parser->nt_headers->OptionalHeader;
    IMAGE_DATA_DIRECTORY *import_dir = &opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dir->VirtualAddress == 0 || import_dir->Size == 0) {
        printf("No import directory found.\n");
        return 0;
    }

    printf("Resolving Imports...\n");

    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)pe_loader_rva_to_va(ctx, import_dir->VirtualAddress);
    if (!desc) {
        fprintf(stderr, "[Error] Import directory RVA 0x%x is out of image bounds\n", import_dir->VirtualAddress);
        return -1;
    }

    // Traverse descriptors until we find an entry where all fields are zero (null descriptor)
    while (desc->Name != 0 || desc->FirstThunk != 0) {
        char *dll_name = (char *)pe_loader_rva_to_va(ctx, desc->Name);
        if (!dll_name) {
            fprintf(stderr, "[Error] DLL Name RVA 0x%x is out of bounds\n", desc->Name);
            return -1;
        }

        printf("Importing from DLL: %s\n", dll_name);

        // OriginalFirstThunk (ILT) and FirstThunk (IAT)
        uint32_t ilt_rva = desc->DUMMYUNIONNAME.OriginalFirstThunk ? desc->DUMMYUNIONNAME.OriginalFirstThunk : desc->FirstThunk;
        IMAGE_THUNK_DATA64 *ilt = (IMAGE_THUNK_DATA64 *)pe_loader_rva_to_va(ctx, ilt_rva);
        IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)pe_loader_rva_to_va(ctx, desc->FirstThunk);

        if (!ilt || !iat) {
            fprintf(stderr, "[Error] ILT or IAT is out of bounds for DLL: %s\n", dll_name);
            return -1;
        }

        // Loop through ILT and IAT entries (both arrays are NULL-terminated)
        while (ilt->u1.AddressOfData != 0) {
            uint64_t resolved_addr = 0;

            // Ordinal check
            if (ilt->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                uint16_t ordinal = ilt->u1.Ordinal & 0xFFFF;
                printf("  [Ordinal] #%u -> Mapped to default mock address\n", ordinal);
                // Map to mock_ExitProcess as fallback
                resolved_addr = (uint64_t)mock_ExitProcess;
            } else {
                // Name check
                IMAGE_IMPORT_BY_NAME *imp_name = (IMAGE_IMPORT_BY_NAME *)pe_loader_rva_to_va(ctx, (uint32_t)ilt->u1.AddressOfData);
                if (!imp_name) {
                    fprintf(stderr, "[Error] Import name RVA 0x%lx is out of bounds\n", ilt->u1.AddressOfData);
                    return -1;
                }
                
                char *func_name = (char *)imp_name->Name;
                printf("  [Function] %s ", func_name);

                // Map mock address based on function name
                if (strcmp(func_name, "ExitProcess") == 0) {
                    resolved_addr = (uint64_t)mock_ExitProcess;
                    printf("-> Resolved to mock_ExitProcess (%p)\n", (void *)resolved_addr);
                } else if (strcmp(func_name, "printf") == 0) {
                    resolved_addr = (uint64_t)mock_printf;
                    printf("-> Resolved to mock_printf (%p)\n", (void *)resolved_addr);
                } else {
                    // Fallback stub
                    resolved_addr = (uint64_t)mock_ExitProcess;
                    printf("-> Resolved to mock_ExitProcess (Fallback, %p)\n", (void *)resolved_addr);
                }
            }

            // Write the resolved address to the IAT
            iat->u1.Function = resolved_addr;

            ilt++;
            iat++;
        }

        desc++;
    }

    printf("Successfully resolved all imports.\n");
    return 0;
}

int pe_loader_apply_protections(pe_loader_context *ctx) {
    if (!ctx || !ctx->loaded_base || !ctx->parser_ctx) {
        return -1;
    }

    pe_parser_context *parser = ctx->parser_ctx;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        page_size = 4096; // fallback
    }

    uint16_t num_sections = parser->nt_headers->FileHeader.NumberOfSections;
    for (uint16_t i = 0; i < num_sections; i++) {
        IMAGE_SECTION_HEADER *sec = &parser->section_headers[i];
        
        int prot = PROT_NONE;
        if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
            prot |= PROT_READ;
        }
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
            prot |= PROT_WRITE;
        }
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            prot |= PROT_EXEC;
        }

        uintptr_t addr = (uintptr_t)ctx->loaded_base + sec->VirtualAddress;
        size_t size = sec->Misc.VirtualSize;

        // mprotect requires page-aligned address and size
        uintptr_t aligned_addr = addr & ~(page_size - 1);
        size_t aligned_size = ((addr + size + page_size - 1) & ~(page_size - 1)) - aligned_addr;

        if (mprotect((void *)aligned_addr, aligned_size, prot) != 0) {
            perror("[Error] mprotect failed");
            return -1;
        }
    }

    return 0;
}

int pe_loader_execute(pe_loader_context *ctx) {
    if (!ctx || !ctx->loaded_base || !ctx->parser_ctx) {
        return -1;
    }

    uint32_t entry_rva = ctx->parser_ctx->nt_headers->OptionalHeader.AddressOfEntryPoint;
    if (entry_rva == 0) {
        fprintf(stderr, "[Error] Entry point RVA is 0, cannot execute.\n");
        return -1;
    }

    void *entry_va = pe_loader_rva_to_va(ctx, entry_rva);
    if (!entry_va) {
        fprintf(stderr, "[Error] Entry point RVA 0x%x is out of image bounds\n", entry_rva);
        return -1;
    }

    printf("Executing Entry Point (VA: %p)...\n\n", entry_va);

    // Cast Entry Point address to ms_abi function pointer (using union to avoid pedantic warnings)
    typedef void (__attribute__((ms_abi)) *pe_entry_fn)(void);
    union {
        void *va;
        pe_entry_fn fn;
    } cast;
    cast.va = entry_va;
    pe_entry_fn entry = cast.fn;

    // Transfer execution control to the PE image entry point
    entry();

    return 0;
}

void *pe_loader_rva_to_va(const pe_loader_context *ctx, uint32_t rva) {
    if (!ctx || !ctx->loaded_base) {
        return NULL;
    }
    if (rva >= ctx->image_size) {
        return NULL;
    }
    return ctx->loaded_base + rva;
}

void pe_loader_free(pe_loader_context *ctx) {
    if (ctx && ctx->loaded_base) {
        munmap(ctx->loaded_base, ctx->image_size);
        ctx->loaded_base = NULL;
        ctx->image_size = 0;
    }
}
