# 🎯 c-threat-hunter

[![Language](https://img.shields.io/badge/Language-C11-00599C?logo=c&logoColor=white)](https://en.cppreference.com/w/c/11)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Programs](https://img.shields.io/badge/Programs-0%2F20-orange)](ROADMAP.md)

> Low-level C programs for malware detection, binary inspection, and system threat hunting — built to understand operating system internals from the ground up.

---

## 📋 Overview

Understanding malware and intrusion techniques requires mastering the operating system at the binary and memory level. **`c-threat-hunter`** is a structured collection of **20 low-level C programs** designed for defensive security analysts, threat hunters, and reverse engineers.

The toolkit explores:
- **Executable File Formats**: Parsing Portable Executable (`.exe`/`.dll`) and Executable and Linkable Format (`ELF`) binaries directly from raw byte streams.
- **Process & Memory Hunting**: Detecting process hollowing, unmapped executable memory (`RWX`), injected DLLs, and suspicious thread start addresses.
- **System Integrity**: Auditing persistence vectors (Run keys, systemd), inline API hooks (`ntdll.dll` patches), and filesystem integrity.

**🗺️ [View the Full Learning Roadmap →](ROADMAP.md)**

---

## 📂 Project Structure

```
c-threat-hunter/
│
├── static-analysis/          # 🔍 Phase 1: Static Binary Analysis
│   ├── pe_header_parser.c          # DOS/NT/Optional headers, sections, imports/exports
│   ├── elf_header_parser.c         # ELF header, program headers, dynamic symbols
│   ├── section_entropy.c           # Shannon entropy algorithm (packed code detection)
│   ├── string_extractor.c          # ASCII and UTF-16LE string carver
│   └── hash_validator.c            # MD5/SHA-256 signature verification
│
├── process-inspection/       # 🛰️ Phase 2: Live Process & Module Inspection
│   ├── proc_enumerator.c           # Process snapshots & parent-child mapping
│   ├── module_scanner.c            # Enumerate loaded DLLs / shared objects
│   ├── thread_checker.c            # Detect unbacked thread start addresses
│   ├── hollowing_detector.c        # In-memory PE vs disk image comparison
│   └── parent_spoof_detector.c     # Validate process lineage baselines
│
├── memory-analysis/          # 🧠 Phase 3: Memory Analysis & Heuristics
│   ├── page_perms_audit.c          # Scan for PAGE_EXECUTE_READWRITE (RWX) allocations
│   ├── pattern_scanner.c           # Fast byte pattern scanning in memory regions
│   ├── memory_dump.c               # Dump suspicious memory regions for analysis
│   ├── vad_tree_walk.c             # Virtual Address Descriptor tracking
│   └── heap_inspector.c            # Process heap enumeration
│
├── system-integrity/         # 🛡️ Phase 4: System Integrity & Persistence
│   ├── autorun_auditor.c           # Registry Run keys & systemd persistence
│   ├── hook_detector.c             # Detect API inline hooks (jmp/detour in ntdll)
│   ├── service_auditor.c           # Service configurations & unquoted path checks
│   ├── driver_enumerator.c         # Loaded kernel driver audit
│   └── fim_monitor.c               # Low-level real-time filesystem monitor
│
├── common/                   # 🛠️ Shared Headers & Utilities
│   ├── utils.h                     # ANSI colors, logging macros, hex dump prototypes
│   └── utils.c                     # Cross-platform utilities implementation
│
├── Makefile                  # Make build system (GCC / Clang / MinGW)
├── CMakeLists.txt            # CMake build system
├── ROADMAP.md                # 20-program roadmap & status
└── LICENSE                   # MIT License
```

---

## ⚙️ Building the Toolkit

### Prerequisites
- A C11-compliant compiler:
  - **Windows**: MinGW-w64 (`gcc`), Clang, or MSVC (`cl.exe`)
  - **Linux**: GCC or Clang (`sudo apt install build-essential`)
- Optional: `make` or `cmake` (version 3.12+)

### Using Make

```bash
# Build all Phase 1 static analysis tools
make static

# Clean build artifacts
make clean
```

### Using Direct Compilation

Each program can be compiled standalone with standard flags:

```bash
# Windows (MinGW)
gcc -Wall -Wextra -std=c11 -Icommon static-analysis/pe_header_parser.c common/utils.c -o bin/pe_parser.exe

# Linux
gcc -Wall -Wextra -std=c11 -Icommon static-analysis/elf_header_parser.c common/utils.c -lm -o bin/elf_parser
```

---

## 📈 Roadmap Progress

| Phase | Category | Programs | Status |
|-------|----------|----------|--------|
| 1 | Static Binary Analysis | 0/5 | ⏳ Up Next |
| 2 | Live Process Inspection | 0/5 | ⬜ Queued |
| 3 | Memory Analysis & Heuristics | 0/5 | ⬜ Queued |
| 4 | System Integrity & Persistence | 0/5 | ⬜ Queued |
| **Total** | | **0/20** | |

---

## ⚠️ Disclaimer

These tools are developed for **defensive security analysis, threat detection, and educational research only**. Always test in controlled virtual machine environments or on authorized systems.

---

## 🤝 About

Built by **[ACESVAGE](https://github.com/ACESVAGE)** — aspiring Security Analyst with a developer's mindset.

Companion repositories:
- [python-security-toolkit](https://github.com/ACESVAGE/python-security-toolkit) — Python security automation and recon tools.
- [linux-admin-scripts](https://github.com/ACESVAGE/linux-admin-scripts) — Linux system administration and hardening scripts.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
