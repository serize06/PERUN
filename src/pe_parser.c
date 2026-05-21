#include "pe_parser.h"
#include <stdio.h>
#include <string.h>

int pe_parser_init(pe_parser_context *ctx, const uint8_t *file_data, size_t file_size) {
    if (!ctx || !file_data || file_size == 0) {
        return -1;
    }
    memset(ctx, 0, sizeof(pe_parser_context));
    ctx->file_data = file_data;
    ctx->file_size = file_size;
    return 0;
}

int pe_parser_parse(pe_parser_context *ctx) {
    if (!ctx || !ctx->file_data) {
        return -1;
    }

    // Minimum file size check for DOS header
    if (ctx->file_size < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "[Error] File size is too small for DOS Header\n");
        return -1;
    }

    ctx->dos_header = (IMAGE_DOS_HEADER *)ctx->file_data;

    // Check MZ Magic
    if (ctx->dos_header->e_magic != 0x5A4D) { // "MZ"
        fprintf(stderr, "[Error] Invalid DOS magic number (expected 0x5A4D, got 0x%04X)\n", ctx->dos_header->e_magic);
        return -1;
    }

    // Offset of NT Headers
    int32_t nt_offset = ctx->dos_header->e_lfanew;
    if (nt_offset < 0 || (size_t)nt_offset + sizeof(IMAGE_NT_HEADERS64) > ctx->file_size) {
        fprintf(stderr, "[Error] Invalid NT headers offset (e_lfanew = %d)\n", nt_offset);
        return -1;
    }

    ctx->nt_headers = (IMAGE_NT_HEADERS64 *)(ctx->file_data + nt_offset);

    // Check PE Signature
    if (ctx->nt_headers->Signature != 0x00004550) { // "PE\0\0"
        fprintf(stderr, "[Error] Invalid PE signature (expected 0x00004550, got 0x%08X)\n", ctx->nt_headers->Signature);
        return -1;
    }

    // Check Machine is AMD64 (x64)
    if (ctx->nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fprintf(stderr, "[Error] Unsupported machine type (expected AMD64 0x8664, got 0x%04X)\n", ctx->nt_headers->FileHeader.Machine);
        return -1;
    }

    // Check Optional Header Magic for PE32+ (0x20B)
    if (ctx->nt_headers->OptionalHeader.Magic != 0x20b) {
        fprintf(stderr, "[Error] Unsupported PE format (expected PE32+ 0x20b, got 0x%04X)\n", ctx->nt_headers->OptionalHeader.Magic);
        return -1;
    }

    // Check Section Headers
    size_t section_offset = (size_t)nt_offset + 4 + sizeof(IMAGE_FILE_HEADER) + ctx->nt_headers->FileHeader.SizeOfOptionalHeader;
    size_t required_size = section_offset + (ctx->nt_headers->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    
    if (required_size > ctx->file_size) {
        fprintf(stderr, "[Error] File size is too small for %d sections\n", ctx->nt_headers->FileHeader.NumberOfSections);
        return -1;
    }

    ctx->section_headers = (IMAGE_SECTION_HEADER *)(ctx->file_data + section_offset);

    return 0;
}

void pe_parser_dump(const pe_parser_context *ctx) {
    if (!ctx || !ctx->nt_headers) {
        return;
    }

    IMAGE_FILE_HEADER *file_hdr = &ctx->nt_headers->FileHeader;
    IMAGE_OPTIONAL_HEADER64 *opt_hdr = &ctx->nt_headers->OptionalHeader;

    printf("Machine: x86_64\n");
    printf("Format: PE32+\n");
    printf("ImageBase: 0x%lx\n", opt_hdr->ImageBase);
    printf("EntryPoint RVA: 0x%x\n", opt_hdr->AddressOfEntryPoint);
    printf("Number of sections: %d\n", file_hdr->NumberOfSections);
    printf("\nSections:\n");

    for (int i = 0; i < file_hdr->NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER *sec = &ctx->section_headers[i];
        
        char name[IMAGE_SIZEOF_SHORT_NAME + 1];
        memcpy(name, sec->Name, IMAGE_SIZEOF_SHORT_NAME);
        name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        
        printf("%-8s RVA=0x%-6x RAW=0x%-6x SIZE=0x%-6x\n",
               name,
               sec->VirtualAddress,
               sec->PointerToRawData,
               sec->Misc.VirtualSize);
    }
}
