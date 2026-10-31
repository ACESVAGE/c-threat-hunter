#include "utils.h"
#include <ctype.h>
#include <math.h>

void utils_enable_ansi(void) {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
}

void utils_hex_dump(const void *buffer, size_t size, uint64_t offset) {
    const uint8_t *data = (const uint8_t *)buffer;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        // Print 64-bit offset
        printf(COLOR_DIM "0x%08llX  " COLOR_RESET, (unsigned long long)(offset + i));

        // Print hex bytes
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        printf(" |");

        // Print ASCII characters
        for (j = 0; j < 16 && (i + j) < size; j++) {
            uint8_t c = data[i + j];
            if (isprint(c)) {
                putchar(c);
            } else {
                printf(COLOR_DIM "." COLOR_RESET);
            }
        }
        printf("|\n");
    }
}

uint8_t *utils_read_file(const char *filepath, size_t *out_size) {
    if (!filepath || !out_size) return NULL;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    if (length < 0) {
        fclose(fp);
        return NULL;
    }
    fseek(fp, 0, SEEK_SET);

    uint8_t *buffer = (uint8_t *)malloc((size_t)length + 1);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    size_t read_bytes = fread(buffer, 1, (size_t)length, fp);
    fclose(fp);

    buffer[read_bytes] = '\0';
    *out_size = read_bytes;
    return buffer;
}

double utils_calculate_entropy(const uint8_t *buffer, size_t size) {
    if (!buffer || size == 0) return 0.0;

    uint64_t counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[buffer[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)size;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}
