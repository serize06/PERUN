#ifndef PERUN_H
#define PERUN_H

#include "pe_parser.h"
#include "pe_loader.h"

typedef struct {
    pe_parser_context parser;
    pe_loader_context loader;
} perun_context;

#endif // PERUN_H
