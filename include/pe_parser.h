#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include "pe_format.h"

typedef struct {
    const uint8_t *file_data;
    size_t file_size;
    
    IMAGE_DOS_HEADER *dos_header;
    IMAGE_NT_HEADERS64 *nt_headers;
    IMAGE_SECTION_HEADER *section_headers;
} pe_parser_context;

int pe_parser_init(pe_parser_context *ctx, const uint8_t *file_data, size_t file_size);
int pe_parser_parse(pe_parser_context *ctx);
void pe_parser_dump(const pe_parser_context *ctx);

#endif // PE_PARSER_H
