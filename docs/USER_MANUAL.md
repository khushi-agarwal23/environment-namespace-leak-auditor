# Environment Variable & Namespace Leak Auditor
## User Manual & Run Instructions

**Operating Systems Lab Project**  
**Module**: Integrated User Guide  
**Lead Maintainer**: Member 3 (Integration, Reporting, and Evaluation)  

---

## 1. Introduction

The **Environment Variable & Namespace Leak Auditor** is a Linux system-programming and security auditing utility. It evaluates:
1. **Process Environment Propagation**: How variables are inherited, sanitized, or stripped across `fork()`, `execve()`, and `waitpid()`.
2. **Namespace Isolation**: Inspects and compares Linux namespace identifiers (`pid`, `mnt`, `net`, `ipc`, `uts`, `user`, `cgroup`, `time`) via `/proc/[PID]/ns`.
3. **Sensitive Exposure Detection**: Identifies sensitive keywords (`PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`, etc.) in memory and emits redacted findings.
4. **Structured Export**: Outputs findings to interactive terminal text, RFC-4180 CSV, and valid JSON.

---

## 2. System Requirements & Prerequisites

- **Operating System**: Linux (Ubuntu 20.04+, Debian, Fedora, Arch) or macOS (Darwin 20.0+)
- **C Compiler**: GCC 9+ or Clang 11+ with C11 standard support
- **Build System**: GNU Make 3.81+
- **Python Runtime (for tests & charts)**: Python 3.8+ with `matplotlib`
- **Shell**: Bash 4.0+ / Zsh

---

## 3. Compilation & Building

The repository features a centralized `Makefile`:

```bash
# Clone or navigate to the repository directory
cd environment-namespace-leak-auditor

# Build all binaries (inspector, auditor, member2, leak_auditor)
make all

# Verify built binaries
ls -l inspector auditor member2 leak_auditor
```

### Make Targets Reference:
- `make all`: Compiles all standalone and integrated tools.
- `make leak_auditor`: Builds only the unified CLI application.
- `make build-member1`: Compiles Member 1 standalone binaries (`inspector`, `auditor`).
- `make build-member2`: Compiles Member 2 standalone binary (`member2`).
- `make test`: Runs the comprehensive automated test suite (`tests/run_all_tests.sh`).
- `make benchmark`: Runs the empirical benchmarking suite and generates graphs.
- `make clean`: Removes all compiled binaries, object files, and test outputs.
- `make help`: Prints make targets and descriptions.

---

## 4. Command-Line Reference (`leak_auditor`)

```
Usage: ./leak_auditor [OPTIONS]

Audit Selection:
  -a, --all               Run all audits (Environment, Namespace, Security) [Default]
  -e, --env-only          Run only the Process & Environment Propagation Engine
  -n, --ns-only           Run only the Linux Namespace Inspection Audit
  -s, --sec-only          Run only the Sensitive Environment Variable Leak Audit

Parameters:
  -p, --pid <PID>         Target process PID for namespace comparison (default: parent PID)

Output & Reporting:
  -f, --format <FMT>      Stdout format: text, json, or csv (default: text)
  -j, --json-out <FILE>   Export structured JSON report to FILE
  -c, --csv-out <FILE>    Export structured CSV report to FILE
  -v, --verbose           Enable verbose diagnostic details
  -q, --quiet             Quiet mode: suppress runtime banners, output format only
      --no-color          Disable ANSI color formatting in terminal output
  -h, --help              Display this help menu and exit
      --version           Display version information and exit
```

---

## 5. Usage Examples

### 5.1 Run Full Comprehensive Audit (Terminal View)
```bash
./leak_auditor
```
Runs the 8 environment inheritance tests, inspects namespaces against the parent PID, scans active environment variables, and prints a formatted terminal report with status indicators.

### 5.2 Run Only Environment Variable Engine
```bash
./leak_auditor --env-only
```
Runs exclusively the process creation tests (`fork()`, `execve()`, `waitpid()`) and reports the status of inherited, sanitized, removed, and absent variables.

### 5.3 Compare Namespaces with a Specific Process (e.g., PID 1)
```bash
./leak_auditor --ns-only --pid 1
```
Reads `/proc/self/ns/*` and `/proc/1/ns/*` using `readlink()` and outputs `SAME`, `DIFFERENT`, or `UNAVAILABLE`.

### 5.4 Export Structured JSON to File
```bash
./leak_auditor -j results/audit.json
```
Saves complete execution records, summary statistics, environment test results, namespace states, and security findings into `results/audit.json`.

### 5.5 Stream JSON to Stdout for Command Pipelines
```bash
./leak_auditor --format json | jq '.summary'
```
Suppresses interactive banners and streams strictly valid JSON suitable for ingestion by `jq`, Python, or cloud log shippers.

### 5.6 Export Structured CSV to File
```bash
./leak_auditor -c results/audit.csv
```
Generates an RFC-4180 compliant CSV file suitable for viewing in Excel, LibreOffice Calc, or Google Sheets.

### 5.7 Run Full Audit and Export Both Formats Simultaneously
```bash
./leak_auditor -j results/report.json -c results/report.csv
```

---

## 6. Standalone Member Modules

Each member's standalone module remains accessible for individual lab grading:

### Member 1: Standalone Environment Engine
```bash
./auditor
```
Runs Member 1's standalone test runner, executing 8 process tests against `./inspector`.

### Member 2: Standalone Namespace & Security Auditor
```bash
# Run against parent process
./member2

# Run against specific target PID
./member2 1
```

---

## 7. Running Tests & Benchmarks

### 7.1 Automated Test Suite
```bash
make test
# OR
./tests/run_all_tests.sh
```
Executes 27 automated tests across 6 suites verifying compilation, unit functionality, CLI parameters, JSON/CSV schemas, and error recovery.

### 7.2 Performance Benchmarks & Graph Generation
```bash
make benchmark
# OR
python3 scripts/benchmark.py && python3 scripts/generate_graphs.py
```
Measures execution time across 50 repeated runs, analyzes scaling behavior across environment sizes up to 1,000 variables, and outputs PNG graphs into `docs/graphs/`.

---

## 8. Exit Codes Reference

| Exit Code | Meaning |
| :---: | :--- |
| `0` | **Success**: All requested audits executed cleanly and all environment tests passed. |
| `1` | **Audit Failure**: At least one environment variable propagation test failed expectation. |
| `2` | **Command Error**: Invalid command-line arguments, bad PID, or missing options. |
