#ifndef THREAT_UTILS_H
#define THREAT_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
    #include <windows.h>
#endif

// ANSI Color Codes
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RED     "\033[91m"
#define COLOR_GREEN   "\033[92m"
#define COLOR_YELLOW  "\033[93m"
#define COLOR_BLUE    "\033[94m"
#define COLOR_CYAN    "\033[96m"
#define COLOR_DIM     "\033[2m"

// Logging macros
#define LOG_INFO(fmt, ...)    printf(COLOR_CYAN "[*] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define LOG_SUCCESS(fmt, ...) printf(COLOR_GREEN "[+] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)    printf(COLOR_YELLOW "[!] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define LOG_ALERT(fmt, ...)   printf(COLOR_RED COLOR_BOLD "[ALERT] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   fprintf(stderr, COLOR_RED "[-] ERROR: " COLOR_RESET fmt "\n", ##__VA_ARGS__)

/**
 * Enable ANSI escape sequence processing on Windows terminals.
 */
void utils_enable_ansi(void);

/**
 * Print a clean, formatted hex dump of a memory buffer.
 *
 * @param buffer Pointer to data
 * @param size   Number of bytes to dump
 * @param offset Starting virtual address / offset label
 */
void utils_hex_dump(const void *buffer, size_t size, uint64_t offset);

/**
 * Read an entire file into memory safely.
 * Returns pointer to buffer (caller must free), or NULL on failure.
 * Populates *out_size with total bytes read.
 */
uint8_t *utils_read_file(const char *filepath, size_t *out_size);

/**
 * Calculate Shannon Entropy of a buffer (range 0.0 to 8.0).
 * Values > 7.0 typically indicate compressed, encrypted, or packed data.
 */
double utils_calculate_entropy(const uint8_t *buffer, size_t size);

#endif // THREAT_UTILS_H
