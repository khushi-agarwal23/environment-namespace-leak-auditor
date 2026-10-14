# Environment Variable & Namespace Leak Auditor
Linux process environment and namespace auditing tool.

**Course**: Operating Systems Laboratory Project  
**Team**: Member 1 (Process & Environment), Member 2 (Namespace & Security), Member 3 (Integration, Reporting & Evaluation)

---

## 1. Project Overview

The **Environment Variable & Namespace Leak Auditor** is a systems programming and security auditing project written in C. It investigates how process creation and program execution affect environment variable inheritance, validates Linux kernel namespace isolation, detects sensitive credential leaks, and exports structured reports.

### Key Capabilities:
- **Process & Environment Engine (Member 1)**: Tests environment variable inheritance, modification, exclusion, and error handling across `fork()`, `execve()`, and `waitpid()`.
- **Namespace & Security Auditor (Member 2)**: Inspects Linux `/proc/[PID]/ns` symbolic links (`pid`, `mnt`, `net`, `ipc`, `uts`, `user`, `cgroup`, `time`) and scans for sensitive environment variables (`PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`, etc.) with automatic value redaction.
- **Integration, Reporting & Evaluation (Member 3)**: Unifies all engines under a flexible CLI (`leak_auditor`), produces machine-readable JSON and RFC-4180 CSV reports, maintains a 27-test automated verification suite, and provides empirical performance benchmarking with publication-ready charts.

---

## 2. Quickstart

### Prerequisites
- GCC or Clang with C11 support
- GNU Make
- Python 3 with `matplotlib` (for test verification & charts)

### Build
```bash
# Clone or navigate to the repository
cd environment-namespace-leak-auditor

# Build all standalone and integrated tools
make all
```

### Run
```bash
# Run comprehensive audit with interactive terminal report
./leak_auditor

# Export structured JSON and CSV reports
./leak_auditor -j results/audit.json -c results/audit.csv

# Run automated test harness (27 tests)
make test

# Run performance benchmarking and generate charts
make benchmark
```

---

## 3. Command-Line Reference (`leak_auditor`)

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

## 4. Repository Structure

```
environment-namespace-leak-auditor/
├── Makefile                          # Unified build automation
├── README.md                         # Project overview and quickstart
├── docs/                             # Project documentation
│   ├── MEMBER3_REPORT.md             # Member 3 Technical Report contribution
│   ├── USER_MANUAL.md                # End-user manual and command reference
│   ├── PRESENTATION_SLIDES.md        # Lab presentation slide deck
│   ├── DEMONSTRATION_GUIDE.md        # Step-by-step viva demo walkthrough
│   ├── member2_workflow.md           # Member 2 module documentation
│   └── graphs/                       # Empirical performance charts
│       ├── benchmark_component_breakdown.png
│       ├── benchmark_env_scaling.png
│       └── benchmark_execution_time.png
├── include/                          # Header files
├── results/                          # Test results and measured data
│   ├── audit_sample.json             # Sample generated JSON audit report
│   ├── audit_sample.csv              # Sample generated CSV audit report
│   ├── benchmark_data.csv            # Raw empirical benchmark measurements
│   ├── performance_results.md        # Measured statistical report
│   ├── member1-test-results.txt      # Member 1 standalone test logs
│   └── member2_results.txt           # Member 2 standalone test logs
├── scripts/                          # Evaluation and visualization scripts
│   ├── benchmark.py                  # Benchmarking suite (latency, scaling)
│   └── generate_graphs.py            # High-resolution matplotlib graph generator
├── src/                              # Source code
│   ├── common.h                      # Shared types, structs, and configuration
│   ├── env_engine.h / .c             # Process & environment propagation library
│   ├── ns_sec_engine.h / .c          # Namespace and security scanning library
│   ├── reporter.h / .c               # Console, JSON, and CSV export engine
│   ├── main.c                        # Unified leak_auditor CLI application
│   ├── auditor.c                     # Member 1 standalone test runner
│   ├── inspector.c                   # Member 1 standalone child inspector
│   └── member2.c                     # Member 2 standalone audit utility
└── tests/                            # Test scripts
    ├── run_all_tests.sh              # 27-test automated verification harness
    └── test_member2.sh               # Member 2 standalone test script
```

---

## 5. Team Roles and Deliverables

| Member | Focus Area | Deliverables |
| :--- | :--- | :--- |
| **Member 1** | Process & Environment Engine | `src/auditor.c`, `src/inspector.c`, `results/member1-test-results.txt` |
| **Member 2** | Namespace & Security Auditor | `src/member2.c`, `tests/test_member2.sh`, `docs/member2_workflow.md` |
| **Member 3** | Integration, Reporting & Evaluation | `src/main.c`, `src/common.h`, `src/env_engine.*`, `src/ns_sec_engine.*`, `src/reporter.*`, `Makefile`, `tests/run_all_tests.sh`, `scripts/benchmark.py`, `scripts/generate_graphs.py`, `results/performance_results.md`, `docs/MEMBER3_REPORT.md`, `docs/USER_MANUAL.md`, `docs/PRESENTATION_SLIDES.md`, `docs/DEMONSTRATION_GUIDE.md` |

---

## 6. License
Academic OS Laboratory Project - Educational Use.
