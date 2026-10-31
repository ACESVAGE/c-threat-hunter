cmake_minimum_required(VERSION 3.12)
project(c_threat_hunter C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

include_directories(common)

# Common utility library
add_library(threat_common STATIC common/utils.c)

# Binary output destination
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

message(STATUS "Configured c-threat-hunter build on ${CMAKE_SYSTEM_NAME}")
