# =============================================================================
# Makefile — c-threat-hunter
# Builds low-level C threat hunting and binary analysis utilities
# Compatible with GCC, Clang, and MinGW
# =============================================================================

CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -O2 -std=c11 -I./common
LDFLAGS ?=

# Windows detection
ifeq ($(OS),Windows_NT)
    EXT = .exe
    RM = del /Q /F
    MKDIR = mkdir
    LDFLAGS += -lpsapi
else
    EXT =
    RM = rm -f
    MKDIR = mkdir -p
    LDFLAGS += -lm
endif

BIN_DIR = bin
COMMON_SRC = common/utils.c
COMMON_OBJ = common/utils.o

all: info

info:
	@echo "=== c-threat-hunter Build System ==="
	@echo "Usage:"
	@echo "  make static       Build Phase 1 (Static Analysis tools)"
	@echo "  make process      Build Phase 2 (Process Inspection tools)"
	@echo "  make memory       Build Phase 3 (Memory Analysis tools)"
	@echo "  make integrity    Build Phase 4 (System Integrity tools)"
	@echo "  make clean        Remove build artifacts and compiled binaries"

clean:
	$(RM) $(COMMON_OBJ)
	$(RM) $(BIN_DIR)/*$(EXT)

.PHONY: all info clean
