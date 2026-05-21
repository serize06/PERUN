cmake_minimum_required(VERSION 3.10)
project(PERUN C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -g)
endif()

# Include directories
include_directories(include)

# Source files
set(SOURCES
    src/main.c
    src/pe_parser.c
    src/pe_loader.c
)

# Executable target
add_executable(perun ${SOURCES})
