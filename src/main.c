#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "perun.h"

void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s <pe_file>          - Load and execute a Windows PE executable\n", prog);
    printf("  %s --info <pe_file>   - Dump headers and section info of the PE\n", prog);
}

int main(int argc, char **argv) {
    const char *pe_path = NULL;
    int dump_info = 0;

    if (argc < 2) {                              // if no input
        print_usage(argv[0]);                    // print usage
        return 1;
    }

    if (strcmp(argv[1], "--info") == 0) {        // if --info is input
        if (argc < 3) {                          // if no pe file
            fprintf(stderr, "[Error] Missing PE file path\n");
            print_usage(argv[0]);
            return 1;
        }
        pe_path = argv[2];                        // set pe path
        dump_info = 1;
    } else if (argv[1][0] == '-') {               // if unknown option is input
        fprintf(stderr, "[Error] Unknown option %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    } else {                                       // if only pe file is input
        pe_path = argv[1];                         // set pe path
    }


    /* Load file into memory */
    FILE *f = fopen(pe_path, "rb");
    if (!f) {                                   // if file not found
        perror("Failed to open file");
        return 1;
    }

    /* 
        why this code need? (move file fonter end -> get file size -> re move??) -> 
        -> frist C language don't have a understand file size from the top. 
        -> we have to move file pointer to end of file to get file size. 
        -> and then move file pointer to beginning of file to read file. 
     */
    fseek(f, 0, SEEK_END);                      // move file pointer to end of file
    long size = ftell(f);                       // get file size
    fseek(f, 0, SEEK_SET);                      // move file pointer to beginning of file

    if (size <= 0) {                            // if file size is 0 or less
        fprintf(stderr, "[Error] Empty file or invalid size\n");
        fclose(f);
        return 1;
    }

    uint8_t *buffer = malloc(size); 
    if (!buffer) {                             // if buffer is not allocated
        fprintf(stderr, "[Error] Memory allocation failed\n");
        fclose(f);
        return 1;
    }

    if (fread(buffer, 1, size, f) != (size_t)size) {    // if buffer size dosen't match with actual file size
        fprintf(stderr, "[Error] Failed to read entire file\n");
        free(buffer);
        fclose(f);
        buffer = NULL;  // protect UAF
        return 1;
    }
    fclose(f);
    f = NULL;       // protect UAF

    perun_context ctx;                                  // this is define in "perun.h"
    memset(&ctx, 0, sizeof(ctx));                       // set buffer to 0

    if (pe_parser_init(&ctx.parser, buffer, size) != 0) { // if buffer dosen't fit to pe file
        fprintf(stderr, "[Error] Initialization of PE parser failed\n");
        free(buffer);
        buffer = NULL;  
        return 1;
    }

    if (pe_parser_parse(&ctx.parser) != 0) {              // if buffer is not fit to pe file and 64 bit dll etc
        fprintf(stderr, "[Error] Parsing of PE file failed\n");
        free(buffer);
        buffer = NULL;  
        return 1;
    }

    if (dump_info) {
        pe_parser_dump(&ctx.parser); // print target CPU Architecture, PE header, Section header, entry point
    } else {
        // Perform loader mapping test
        if (pe_loader_init(&ctx.loader, &ctx.parser) != 0) { // set ctx.loader 0
            fprintf(stderr, "[Error] Initialization of PE loader failed\n");
            free(buffer);
            buffer = NULL;  
            return 1;
        }

        if (pe_loader_map(&ctx.loader) != 0) { // allocate memory in linux to apply section protection
            fprintf(stderr, "[Error] Mapping PE sections failed\n");
            pe_loader_free(&ctx.loader);
            free(buffer);
            return 1;
        }

        if (pe_loader_relocate(&ctx.loader) != 0) { // apply base relocations
            fprintf(stderr, "[Error] Applying relocations failed\n");
            pe_loader_free(&ctx.loader);
            free(buffer);
            buffer = NULL;
            return 1;
        }

        if (pe_loader_resolve_imports(&ctx.loader) != 0) { // resolve import address table
            fprintf(stderr, "[Error] Resolving imports failed\n");
            pe_loader_free(&ctx.loader);
            free(buffer);
            buffer = NULL;
            return 1;
        }

        if (pe_loader_apply_protections(&ctx.loader) != 0) { // apply page protection
            fprintf(stderr, "[Error] Applying memory protections failed\n");
            pe_loader_free(&ctx.loader);
            free(buffer);
            buffer = NULL;  
            return 1;
        }

        printf("Successfully mapped and loaded PE in memory!\n");
        printf("Allocated Base VA: %p\n", (void *)ctx.loader.loaded_base);
        printf("SizeOfImage: 0x%zx\n", ctx.loader.image_size);
        printf("\nMapped Sections:\n");

        for (int i = 0; i < ctx.parser.nt_headers->FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER *sec = &ctx.parser.section_headers[i];
            void *va = pe_loader_rva_to_va(&ctx.loader, sec->VirtualAddress); // exchange RVA to VA
            
            // section name can't be longer than 8bytes
            // we need to copy section name to local variable
            char name[IMAGE_SIZEOF_SHORT_NAME + 1]; // local var
            memcpy(name, sec->Name, IMAGE_SIZEOF_SHORT_NAME);
            name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            
            printf("  %-8s RVA=0x%-6x -> Memory VA=%p (Size=0x%-6x)\n",
                name, sec->VirtualAddress, va, sec->Misc.VirtualSize);
            
            // Debug check for the relocation patch inside the .text section
            if (strcmp(name, ".text") == 0) {
                uint64_t *ptr = (uint64_t *)((uint8_t *)va + 0x10);
                printf("    -> [Debug] Value at .text+0x10 (relocated ptr): %p (expected to match .data VA)\n", (void *)*ptr);
            }
            
            // Debug check for the IAT resolution inside the .idata section
            if (strcmp(name, ".idata") == 0) {
                uint64_t *ptr = (uint64_t *)((uint8_t *)va + 0x40);
                printf("    -> [Debug] Value at .idata+0x40 (resolved IAT entry): %p\n", (void *)*ptr);
            }
        }

        printf("\nStarting execution flow...\n");
        if (pe_loader_execute(&ctx.loader) != 0) {
            fprintf(stderr, "[Error] Executing entry point failed\n");
            pe_loader_free(&ctx.loader);
            free(buffer);
            buffer = NULL;
            return 1;
        }

        pe_loader_free(&ctx.loader);
    }

    free(buffer);
    return 0;
}
