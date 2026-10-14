CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c11 -pedantic -O2
INCLUDES = -Isrc

SRCS_CORE = src/env_engine.c src/ns_sec_engine.c src/reporter.c
SRCS_CLI  = src/main.c $(SRCS_CORE)

BIN_INSPECTOR = inspector
BIN_AUDITOR   = auditor
BIN_MEMBER2   = member2
BIN_UNIFIED   = leak_auditor

ALL_BINS = $(BIN_INSPECTOR) $(BIN_AUDITOR) $(BIN_MEMBER2) $(BIN_UNIFIED)

.PHONY: all clean test benchmark help build-member1 build-member2 build-unified

all: $(ALL_BINS)

$(BIN_INSPECTOR): src/inspector.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

$(BIN_AUDITOR): src/auditor.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

$(BIN_MEMBER2): src/member2.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

$(BIN_UNIFIED): $(SRCS_CLI) src/common.h src/env_engine.h src/ns_sec_engine.h src/reporter.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRCS_CLI)

build-member1: $(BIN_INSPECTOR) $(BIN_AUDITOR)

build-member2: $(BIN_MEMBER2)

build-unified: $(BIN_UNIFIED)

test: all
	@chmod +x tests/run_all_tests.sh
	@./tests/run_all_tests.sh

benchmark: all
	@python3 scripts/benchmark.py
	@python3 scripts/generate_graphs.py

clean:
	rm -f $(ALL_BINS) *.o
	rm -f results/audit_test_*.json results/audit_test_*.csv
	rm -f test_env_*.tmp
	@echo "Clean completed."

help:
	@echo "Environment Variable & Namespace Leak Auditor - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all         Build all binaries (inspector, auditor, member2, leak_auditor)"
	@echo "  leak_auditor Build the integrated Member 3 unified auditor"
	@echo "  member1     Build Member 1 standalone binaries (inspector, auditor)"
	@echo "  member2     Build Member 2 standalone binary (member2)"
	@echo "  test        Run the automated test suite"
	@echo "  benchmark   Run performance benchmark and generate graphs"
	@echo "  clean       Remove built binaries and temporary test files"
	@echo "  help        Display this help message"
