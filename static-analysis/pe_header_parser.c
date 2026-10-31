/**
 * ============================================================================
 * pe_header_parser.c — Program #01 in c-threat-hunter
 * Phase 1: Static Binary Analysis
 * ============================================================================
 * Parses Windows Portable Executable (PE32 / PE32+) binaries directly from raw
 * byte streams. Inspects DOS Header, COFF File Header, Optional Header, and
 * Section Tables. Computes section entropy and flags packer / malware indicators.
 *
 * Compiles on: Windows (MSVC/MinGW/Clang), Linux (GCC/Clang), macOS.
 *
 * Usage:
 *   ./pe_parser <target.exe>
 *   ./pe_parser <target.exe> --sections
 *   ./pe_parser <target.exe> --json
 * ============================================================================
 */

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#pragma pack(push, 1)

/* --- DOS Header (64 bytes) --- */
typedef struct {
    uint16_t e_magic;      // Magic number ('MZ' = 0x5A4D)
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;     // File address of new exe header (PE)
} PeDosHeader;

/* --- COFF File Header (20 bytes) --- */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PeFileHeader;

/* --- Data Directory (8 bytes) --- */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} PeDataDirectory;

/* --- Optional Header (PE32 / 32-bit) --- */
typedef struct {
    uint16_t        Magic;                 // 0x010B
    uint8_t         MajorLinkerVersion;
    uint8_t         MinorLinkerVersion;
    uint32_t        SizeOfCode;
    uint32_t        SizeOfInitializedData;
    uint32_t        SizeOfUninitializedData;
    uint32_t        AddressOfEntryPoint;
    uint32_t        BaseOfCode;
    uint32_t        BaseOfData;
    uint32_t        ImageBase;
    uint32_t        SectionAlignment;
    uint32_t        FileAlignment;
    uint16_t        MajorOperatingSystemVersion;
    uint16_t        MinorOperatingSystemVersion;
    uint16_t        MajorImageVersion;
    uint16_t        MinorImageVersion;
    uint16_t        MajorSubsystemVersion;
    uint16_t        MinorSubsystemVersion;
    uint32_t        Win32VersionValue;
    uint32_t        SizeOfImage;
    uint32_t        SizeOfHeaders;
    uint32_t        CheckSum;
    uint16_t        Subsystem;
    uint16_t        DllCharacteristics;
    uint32_t        SizeOfStackReserve;
    uint32_t        SizeOfStackCommit;
    uint32_t        SizeOfHeapReserve;
    uint32_t        SizeOfHeapCommit;
    uint32_t        LoaderFlags;
    uint32_t        NumberOfRvaAndSizes;
    PeDataDirectory DataDirectory[16];
} PeOptionalHeader32;

/* --- Optional Header (PE32+ / 64-bit) --- */
typedef struct {
    uint16_t        Magic;                 // 0x020B
    uint8_t         MajorLinkerVersion;
    uint8_t         MinorLinkerVersion;
    uint32_t        SizeOfCode;
    uint32_t        SizeOfInitializedData;
    uint32_t        SizeOfUninitializedData;
    uint32_t        AddressOfEntryPoint;
    uint32_t        BaseOfCode;
    uint64_t        ImageBase;
    uint32_t        SectionAlignment;
    uint32_t        FileAlignment;
    uint16_t        MajorOperatingSystemVersion;
    uint16_t        MinorOperatingSystemVersion;
    uint16_t        MajorImageVersion;
    uint16_t        MinorImageVersion;
    uint16_t        MajorSubsystemVersion;
    uint16_t        MinorSubsystemVersion;
    uint32_t        Win32VersionValue;
    uint32_t        SizeOfImage;
    uint32_t        SizeOfHeaders;
    uint32_t        CheckSum;
    uint16_t        Subsystem;
    uint16_t        DllCharacteristics;
    uint64_t        SizeOfStackReserve;
    uint64_t        SizeOfStackCommit;
    uint64_t        SizeOfHeapReserve;
    uint64_t        SizeOfHeapCommit;
    uint32_t        LoaderFlags;
    uint32_t        NumberOfRvaAndSizes;
    PeDataDirectory DataDirectory[16];
} PeOptionalHeader64;

/* --- Section Header (40 bytes) --- */
typedef struct {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} PeSectionHeader;

#pragma pack(pop)

/* Constants */
#define IMAGE_DOS_SIGNATURE     0x5A4D       // "MZ"
#define IMAGE_NT_SIGNATURE      0x00004550   // "PE\0\0"
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

/* Section Characteristics Flags */
#define SCN_MEM_EXECUTE         0x20000000
#define SCN_MEM_READ            0x40000000
#define SCN_MEM_WRITE           0x80000000
#define SCN_CNT_CODE            0x00000020
#define SCN_CNT_INITIALIZED     0x00000040
#define SCN_CNT_UNINITIALIZED   0x00000080

/* Machine Architecture Constants */
#define MACHINE_I386    0x014C
#define MACHINE_AMD64   0x8664
#define MACHINE_ARM     0x01C0
#define MACHINE_ARM64   0xAA64

static const char *get_machine_name(uint16_t machine) {
    switch (machine) {
        case MACHINE_I386:  return "Intel 386 (x86 32-bit)";
        case MACHINE_AMD64: return "AMD64 / x86-64 (64-bit)";
        case MACHINE_ARM:   return "ARM Little-Endian";
        case MACHINE_ARM64: return "ARM64 Little-Endian";
        default:            return "Unknown / Other Architecture";
    }
}

static const char *get_subsystem_name(uint16_t subsystem) {
    switch (subsystem) {
        case 1:  return "Native (Device Driver)";
        case 2:  return "Windows GUI";
        case 3:  return "Windows CUI (Console Application)";
        case 5:  return "OS/2 Console";
        case 7:  return "POSIX Console";
        case 9:  return "Windows CE GUI";
        case 10: return "EFI Application";
        case 14: return "XBOX";
        default: return "Unknown Subsystem";
    }
}

static void format_timestamp(uint32_t timestamp, char *out_buf, size_t buf_size) {
    time_t raw_time = (time_t)timestamp;
    struct tm *time_info = gmtime(&raw_time);
    if (time_info) {
        strftime(out_buf, buf_size, "%Y-%m-%d %H:%M:%S UTC", time_info);
    } else {
        snprintf(out_buf, buf_size, "Invalid Timestamp (0x%08X)", timestamp);
    }
}

static void get_section_perms(uint32_t chars, char *out) {
    out[0] = (chars & SCN_MEM_READ)    ? 'R' : '-';
    out[1] = (chars & SCN_MEM_WRITE)   ? 'W' : '-';
    out[2] = (chars & SCN_MEM_EXECUTE) ? 'X' : '-';
    out[3] = '\0';
}

static void print_banner(void) {
    printf("%s%s", COLOR_CYAN, COLOR_BOLD);
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║             🎯  PE HEADER PARSER & THREAT ANALYZER                ║\n");
    printf("║             c-threat-hunter • Phase 1: Static Analysis             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    printf("%s\n", COLOR_RESET);
}

int main(int argc, char *argv[]) {
    utils_enable_ansi();

    if (argc < 2) {
        print_banner();
        fprintf(stderr, "Usage: %s <binary_file.exe|dll> [--sections] [--json]\n\n", argv[0]);
        fprintf(stderr, "Flags:\n");
        fprintf(stderr, "  --sections   Print detailed section inspection only\n");
        fprintf(stderr, "  --json       Export parsed structure as JSON payload\n");
        return 1;
    }

    const char *filepath = argv[1];
    bool show_sections_only = false;
    bool output_json = false;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--sections") == 0) show_sections_only = true;
        else if (strcmp(argv[i], "--json") == 0) output_json = true;
    }

    size_t file_size = 0;
    uint8_t *file_buf = utils_read_file(filepath, &file_size);
    if (!file_buf) {
        LOG_ERROR("Failed to open or read file: '%s'", filepath);
        return 2;
    }

    // 1. Validate DOS Header
    if (file_size < sizeof(PeDosHeader)) {
        LOG_ERROR("File too small to contain a valid DOS Header (%zu bytes)", file_size);
        free(file_buf);
        return 3;
    }

    PeDosHeader *dos_hdr = (PeDosHeader *)file_buf;
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERROR("Invalid DOS Signature (0x%04X, expected 0x5A4D 'MZ')", dos_hdr->e_magic);
        free(file_buf);
        return 4;
    }

    // 2. Locate NT Headers via e_lfanew
    if (dos_hdr->e_lfanew <= 0 || (size_t)dos_hdr->e_lfanew + 4 + sizeof(PeFileHeader) > file_size) {
        LOG_ERROR("Corrupt or invalid PE offset: e_lfanew = 0x%X", dos_hdr->e_lfanew);
        free(file_buf);
        return 5;
    }

    uint8_t *nt_ptr = file_buf + dos_hdr->e_lfanew;
    uint32_t pe_sig = *(uint32_t *)nt_ptr;
    if (pe_sig != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Invalid PE Signature (0x%08X, expected 0x00004550 'PE\\0\\0')", pe_sig);
        free(file_buf);
        return 6;
    }

    // 3. Parse COFF File Header
    PeFileHeader *file_hdr = (PeFileHeader *)(nt_ptr + 4);
    uint8_t *opt_ptr = nt_ptr + 4 + sizeof(PeFileHeader);

    // 4. Parse Optional Header (check 32-bit vs 64-bit)
    uint16_t opt_magic = *(uint16_t *)opt_ptr;
    bool is_64bit = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    uint64_t image_base = 0;
    uint32_t entry_point = 0;
    uint32_t size_of_image = 0;
    uint16_t subsystem = 0;

    if (is_64bit) {
        PeOptionalHeader64 *opt64 = (PeOptionalHeader64 *)opt_ptr;
        image_base = opt64->ImageBase;
        entry_point = opt64->AddressOfEntryPoint;
        size_of_image = opt64->SizeOfImage;
        subsystem = opt64->Subsystem;
    } else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PeOptionalHeader32 *opt32 = (PeOptionalHeader32 *)opt_ptr;
        image_base = opt32->ImageBase;
        entry_point = opt32->AddressOfEntryPoint;
        size_of_image = opt32->SizeOfImage;
        subsystem = opt32->Subsystem;
    }

    // 5. Parse Section Headers
    uint8_t *sec_ptr = opt_ptr + file_hdr->SizeOfOptionalHeader;
    size_t num_sections = file_hdr->NumberOfSections;
    PeSectionHeader *sections = (PeSectionHeader *)sec_ptr;

    char time_str[64];
    format_timestamp(file_hdr->TimeDateStamp, time_str, sizeof(time_str));

    // Threat heuristics counters
    int rwx_sections = 0;
    int high_entropy_sections = 0;

    if (output_json) {
        printf("{\n");
        printf("  \"file\": \"%s\",\n", filepath);
        printf("  \"file_size\": %zu,\n", file_size);
        printf("  \"architecture\": \"%s\",\n", get_machine_name(file_hdr->Machine));
        printf("  \"is_64bit\": %s,\n", is_64bit ? "true" : "false");
        printf("  \"timestamp\": \"%s\",\n", time_str);
        printf("  \"entry_point\": \"0x%X\",\n", entry_point);
        printf("  \"image_base\": \"0x%llX\",\n", (unsigned long long)image_base);
        printf("  \"size_of_image\": %u,\n", size_of_image);
        printf("  \"subsystem\": \"%s\",\n", get_subsystem_name(subsystem));
        printf("  \"num_sections\": %zu,\n", num_sections);
        printf("  \"sections\": [\n");

        for (size_t i = 0; i < num_sections; i++) {
            char sec_name[9] = {0};
            memcpy(sec_name, sections[i].Name, 8);

            double entropy = 0.0;
            if (sections[i].PointerToRawData + sections[i].SizeOfRawData <= file_size && sections[i].SizeOfRawData > 0) {
                entropy = utils_calculate_entropy(file_buf + sections[i].PointerToRawData, sections[i].SizeOfRawData);
            }

            char perms[4];
            get_section_perms(sections[i].Characteristics, perms);

            printf("    {\n");
            printf("      \"name\": \"%s\",\n", sec_name);
            printf("      \"virtual_address\": \"0x%X\",\n", sections[i].VirtualAddress);
            printf("      \"virtual_size\": %u,\n", sections[i].VirtualSize);
            printf("      \"raw_size\": %u,\n", sections[i].SizeOfRawData);
            printf("      \"raw_offset\": \"0x%X\",\n", sections[i].PointerToRawData);
            printf("      \"permissions\": \"%s\",\n", perms);
            printf("      \"entropy\": %.3f\n", entropy);
            printf("    }%s\n", (i + 1 < num_sections) ? "," : "");
        }
        printf("  ]\n");
        printf("}\n");

        free(file_buf);
        return 0;
    }

    if (!show_sections_only) {
        print_banner();
        printf("%sTarget Binary  :%s %s%s%s\n", COLOR_BOLD, COLOR_RESET, COLOR_GREEN, filepath, COLOR_RESET);
        printf("%sFile Size      :%s %zu bytes\n", COLOR_BOLD, COLOR_RESET, file_size);
        printf("%sArchitecture   :%s %s (%s)\n", COLOR_BOLD, COLOR_RESET, get_machine_name(file_hdr->Machine), is_64bit ? "64-bit" : "32-bit");
        printf("%sCompiled At    :%s %s%s%s\n", COLOR_BOLD, COLOR_RESET, COLOR_YELLOW, time_str, COLOR_RESET);
        printf("%sEntry Point    :%s 0x%08X (RVA)\n", COLOR_BOLD, COLOR_RESET, entry_point);
        printf("%sImage Base     :%s 0x%016llX\n", COLOR_BOLD, COLOR_RESET, (unsigned long long)image_base);
        printf("%sSubsystem      :%s %s\n\n", COLOR_BOLD, COLOR_RESET, get_subsystem_name(subsystem));
    }

    printf("%s%s━━━ SECTION TABLE INSPECTION (%zu sections) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", COLOR_CYAN, COLOR_BOLD, num_sections, COLOR_RESET);
    printf(" %-8s  %-10s  %-10s  %-10s  %-5s  %-7s  %-12s\n",
           "NAME", "VIRT_ADDR", "VIRT_SIZE", "RAW_SIZE", "PERM", "ENTROPY", "HEURISTICS");
    printf(" ──────────────────────────────────────────────────────────────────────────\n");

    for (size_t i = 0; i < num_sections; i++) {
        char sec_name[9] = {0};
        memcpy(sec_name, sections[i].Name, 8);

        char perms[4];
        get_section_perms(sections[i].Characteristics, perms);

        double entropy = 0.0;
        if (sections[i].PointerToRawData + sections[i].SizeOfRawData <= file_size && sections[i].SizeOfRawData > 0) {
            entropy = utils_calculate_entropy(file_buf + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }

        // Heuristics checks
        bool is_rwx = (sections[i].Characteristics & SCN_MEM_WRITE) && (sections[i].Characteristics & SCN_MEM_EXECUTE);
        bool is_packed = (entropy > 7.0);

        if (is_rwx) rwx_sections++;
        if (is_packed) high_entropy_sections++;

        const char *heuristic_tag = "";
        if (is_rwx && is_packed) {
            heuristic_tag = COLOR_RED COLOR_BOLD "[RWX + PACKED]" COLOR_RESET;
        } else if (is_rwx) {
            heuristic_tag = COLOR_RED "[RWX WARNING]" COLOR_RESET;
        } else if (is_packed) {
            heuristic_tag = COLOR_YELLOW "[HIGH ENTROPY]" COLOR_RESET;
        } else {
            heuristic_tag = COLOR_DIM "Normal" COLOR_RESET;
        }

        printf(" %-8s  0x%08X  0x%08X  0x%08X  %-5s  %5.3f    %s\n",
               sec_name,
               sections[i].VirtualAddress,
               sections[i].VirtualSize,
               sections[i].SizeOfRawData,
               perms,
               entropy,
               heuristic_tag);
    }

    printf(" ──────────────────────────────────────────────────────────────────────────\n");

    // Threat Assessment Summary
    printf("\n%s%s━━━ HEURISTIC THREAT ASSESSMENT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", COLOR_CYAN, COLOR_BOLD, COLOR_RESET);
    if (rwx_sections > 0) {
        LOG_ALERT("Found %d section(s) marked Writable & Executable (RWX) — high risk indicator for shellcode or self-modifying unpackers!", rwx_sections);
    } else {
        LOG_SUCCESS("No RWX sections detected. Code and write permissions are segregated.");
    }

    if (high_entropy_sections > 0) {
        LOG_WARN("Found %d section(s) with high Shannon entropy (>7.0) — potential payload encryption or packing (e.g. UPX).", high_entropy_sections);
    } else {
        LOG_SUCCESS("Section entropy levels within standard compiled ranges (<7.0).");
    }

    printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", COLOR_DIM, COLOR_RESET);

    free(file_buf);
    return 0;
}
