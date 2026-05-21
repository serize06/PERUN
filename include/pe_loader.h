#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include "pe_parser.h"

typedef struct {
    uint8_t *loaded_base; // Actual loaded virtual memory base address in Linux
    size_t image_size;    // SizeOfImage
    pe_parser_context *parser_ctx;
} pe_loader_context;

int pe_loader_init(pe_loader_context *ctx, pe_parser_context *parser_ctx);
int pe_loader_map(pe_loader_context *ctx);
int pe_loader_relocate(pe_loader_context *ctx);
int pe_loader_apply_protections(pe_loader_context *ctx);
void *pe_loader_rva_to_va(const pe_loader_context *ctx, uint32_t rva);
void pe_loader_free(pe_loader_context *ctx);

#endif // PE_LOADER_H
