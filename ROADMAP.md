# 🎯 c-threat-hunter — Learning & Implementation Roadmap

> Low-level C programs for malware detection, binary analysis, and system threat hunting.
> Each program explores low-level OS internals (Windows PE / Win32 & Linux ELF / POSIX).
> Repository: [ACESVAGE/c-threat-hunter](https://github.com/ACESVAGE/c-threat-hunter)

---

## 🔍 Phase 1 — Static Binary Analysis
*Analyze executable file structures on disk without executing them.*

| # | Program | Folder | Concepts Covered | Status |
|---|---------|--------|-----------------|--------|
| 1 | `pe_header_parser.c` | `static-analysis/` | DOS/PE headers, sections (.text, .data), imports/exports, compilation timestamps | ✅ Done |
| 2 | `elf_header_parser.c` | `static-analysis/` | ELF ident, architecture, program headers, section headers, dynamic symbols | ⏳ Next |
| 3 | `section_entropy.c` | `static-analysis/` | Shannon entropy algorithm, detect packed/encrypted payloads (>7.0 entropy) | ⬜ |
| 4 | `string_extractor.c` | `static-analysis/` | Extract ASCII and UTF-16LE strings (C2 URLs, IPs, commands, registry keys) | ⬜ |
| 5 | `hash_validator.c` | `static-analysis/` | Compute raw MD5 & SHA-256 binary digests for threat feed matching | ⬜ |

---

## 🛰️ Phase 2 — Live Process & Module Inspection
*Inspect running processes, DLL injections, and suspicious execution patterns.*

| # | Program | Folder | Concepts Covered | Status |
|---|---------|--------|-----------------|--------|
| 6 | `proc_enumerator.c` | `process-inspection/` | Process snapshots (`CreateToolhelp32Snapshot` / `/proc`), PID, PPID, path mapping | ⬜ |
| 7 | `module_scanner.c` | `process-inspection/` | Enumerate loaded DLLs / shared objects (`EnumProcessModules`), detect unlinked modules | ⬜ |
| 8 | `thread_checker.c` | `process-inspection/` | Enumerate threads, detect start addresses outside known module memory space | ⬜ |
| 9 | `hollowing_detector.c` | `process-inspection/` | Compare in-memory PE headers vs disk image to identify Process Hollowing | ⬜ |
| 10 | `parent_spoof_detector.c`| `process-inspection/` | Validate parent-child process tree relationships against known normal baselines | ⬜ |

---

## 🧠 Phase 3 — Memory Analysis & Heuristics
*Audit virtual memory allocations and hunt for in-memory payloads.*

| # | Program | Folder | Concepts Covered | Status |
|---|---------|--------|-----------------|--------|
| 11 | `page_perms_audit.c` | `memory-analysis/` | Scan for `PAGE_EXECUTE_READWRITE` (RWX) memory pages (shellcode indicators) | ⬜ |
| 12 | `pattern_scanner.c` | `memory-analysis/` | Fast byte signature / regex scanning inside remote process memory regions | ⬜ |
| 13 | `memory_dump.c` | `memory-analysis/` | Safely dump suspicious allocated memory regions to disk for offline analysis | ⬜ |
| 14 | `vad_tree_walk.c` | `memory-analysis/` | Virtual Address Descriptor inspection concepts and committed memory tracking | ⬜ |
| 15 | `heap_inspector.c` | `memory-analysis/` | Enumerate process heaps and identify abnormal allocation blocks | ⬜ |

---

## 🛡️ Phase 4 — System Integrity & Persistence Auditing
*Detect persistence mechanisms, rootkit hooks, and unauthorized modifications.*

| # | Program | Folder | Concepts Covered | Status |
|---|---------|--------|-----------------|--------|
| 16 | `autorun_auditor.c` | `system-integrity/` | Enumerate Windows Run/RunOnce registry keys and Linux systemd services | ⬜ |
| 17 | `hook_detector.c` | `system-integrity/` | Read loaded `ntdll.dll` memory, detect inline function detours (`JMP`/`0xE9` patches) | ⬜ |
| 18 | `service_auditor.c` | `system-integrity/` | Enumerate Win32 service configurations and binary paths for unquoted path vulnerabilities | ⬜ |
| 19 | `driver_enumerator.c` | `system-integrity/` | Enumerate loaded kernel drivers (`EnumDeviceDrivers`) and check signatures | ⬜ |
| 20 | `fim_monitor.c` | `system-integrity/` | Real-time directory change monitoring (`ReadDirectoryChangesW` / `inotify`) | ⬜ |

---

## 🗓️ Learning Session Workflow

Each session we will:
1. **Review** core C / OS internal concepts (structs, pointers, API calls)
2. **Implement** the program with defensive error checking and memory safety
3. **Verify** compilation with warnings enabled (`-Wall -Wextra -Wpedantic`)
4. **Commit & Push** to GitHub and advance roadmap status

---

## 🔑 Legend
| Symbol | Meaning |
|--------|---------|
| ✅ Done | Program implemented, tested, and pushed |
| ⏳ Next | Next program to be developed |
| ⬜ Queued | Scheduled for upcoming session |

---

*Last updated: 2026-10-31 • Roadmap version 1.0*
