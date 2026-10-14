# Member 3 Technical Report: Integration, Reporting, and Evaluation
**Operating Systems Lab Project**  
**Project Title**: Environment Variable & Namespace Leak Auditor  
**Module**: Integration, Reporting, and Performance Evaluation  
**Role Owner**: Member 3  

---

## 1. Executive Summary

In modern operating systems, process creation, execution, and security isolation are fundamental topics. When a parent process spawns a child via `fork()` and replaces the address space using `execve()`, environment variables are by default inherited through the global pointer `environ`. If sensitive data (such as API keys, tokens, or credentials) reside in the parent process's environment, unintentional leakage to child processes or third-party executables can occur. Concurrently, Linux namespaces provide isolated views of global system resources (PID, Mount, Network, IPC, UTS, User, Cgroup, Time).

While **Member 1** developed the process creation and environment variable propagation engine and **Member 2** developed the Linux namespace inspector and security keyword detector, **Member 3** was tasked with **Integration, Reporting, and Performance Evaluation**.

This document outlines the engineering work performed by Member 3:
1. **Modular Integration**: Unifying disparate modules into a cohesive CLI (`leak_auditor`) with decoupled C libraries (`env_engine`, `ns_sec_engine`, `reporter`).
2. **Structured Reporting**: Engineering RFC-4180 compliant CSV export and schema-validated JSON serialization for automated processing.
3. **Automated Testing**: Designing a comprehensive 27-test validation suite covering unit verification, integrated flags, JSON/CSV parsing, and OS edge cases.
4. **Empirical Benchmarking**: Conducting empirical timing experiments on process lifecycle and scaling behavior, generating statistical tables and publication-grade graphs without fabricated data.
5. **Lab Deliverables**: Authoring the User Manual, Demonstration Guide, and Slide Deck for the final laboratory defense.

---

## 2. System Architecture & Integration Model

### 2.1 Unified Architecture

The system is organized into modular layers designed to maintain high cohesion and low coupling:

```
                       +----------------------------------+
                       |       leak_auditor (main.c)      |
                       |       Command-Line Interface     |
                       +-----------------+----------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
+--------v---------+           +---------v----------+           +--------v---------+
|   env_engine     |           |   ns_sec_engine    |           |     reporter     |
| (Member 1 Logic) |           |  (Member 2 Logic)  |           | (Member 3 Logic) |
+--------+---------+           +---------+----------+           +--------+---------+
         |                               |                               |
         | fork(), execve(),             | /proc/[PID]/ns readlink()     | Console Text
         | waitpid() across              | environ keyword scan          | Valid JSON
         | 8 controlled tests            | value redaction               | Valid CSV
         v                               v                               v
[ Child Process: inspector ]     [ Linux Kernel /proc / Memory ]   [ Terminal / File ]
```

### 2.2 Shared Data Structures (`src/common.h`)

To eliminate hardcoded global coupling between modules, Member 3 designed unified C data structures:

```c
typedef struct {
    int test_id;
    char name[STR_BUF_SMALL];
    char description[STR_BUF_MED];
    char target_var[STR_BUF_SMALL];
    char expectation[STR_BUF_SMALL];
    int expected_exit;
    int actual_exit;
    bool passed;
    char details[STR_BUF_MED];
} env_test_record_t;

typedef struct {
    char name[STR_BUF_SMALL];     /* pid, mnt, net, ipc, uts, user, cgroup, time */
    char self_ns[STR_BUF_MED];    /* symlink e.g. pid:[4026532225] */
    char target_ns[STR_BUF_MED];  /* target comparison process symlink */
    ns_status_t status;           /* SAME, DIFFERENT, UNAVAILABLE */
    char error_msg[STR_BUF_SMALL];
} ns_record_t;

typedef struct {
    char var_name[STR_BUF_MED];
    char redacted_value[STR_BUF_SMALL]; /* "[REDACTED]" */
    char level[STR_BUF_SMALL];          /* "REVIEW REQUIRED" */
    char recommendation[STR_BUF_MED];
    char matched_pattern[STR_BUF_SMALL];
} sec_finding_t;
```

These structures are aggregated into an `audit_report_t` instance that holds complete execution metadata, allowing any formatter to serialize the audit state deterministically.

---

## 3. Structured Output & Reporting Engine

A core responsibility of Member 3 is producing structured, machine-readable output to integrate with security pipelines, log aggregators, and data analysis software.

### 3.1 JSON Export Specification (`--format json`, `-j <file>`)

The JSON generator (`src/reporter.c`) implements character-level escaping for strings (`"`, `\`, control codes) and outputs standard JSON. The following is an illustrative example, not the latest WSL2 benchmark output:

```json
{
  "project": "Environment Variable & Namespace Leak Auditor",
  "schema_version": "1.0.0",
  "timestamp": "2026-10-14T13:20:41+0530",
  "system": {
    "os": "Darwin arm64",
    "kernel": "24.6.0",
    "auditor_pid": 27564
  },
  "summary": {
    "environment_tests_total": 8,
    "environment_tests_passed": 8,
    "environment_tests_failed": 0,
    "namespaces_total": 8,
    "namespaces_matching": 0,
    "namespaces_different": 0,
    "namespaces_unavailable": 8,
    "environment_variables_scanned": 48,
    "security_findings_total": 3
  },
  "environment_tests": [ ... ],
  "namespace_audit": { ... },
  "security_findings": [ ... ]
}
```

### 3.2 CSV Export Specification (`--format csv`, `-c <file>`)

The CSV generator formats data in compliance with RFC-4180 with standard escaping. Fields:
`Section, Identifier, Property, Value, Status, Recommendation`

Example rows:
```csv
Section,Identifier,Property,Value,Status,Recommendation
Metadata,Header,Timestamp,2026-10-14T13:20:57+0530,INFO,-
EnvironmentTest,TEST_1,Inherited Variable Propagation,Child 27622 exited with expected code 0,PASS,-
Namespace,pid,LinkComparison,Self: N/A | Target: N/A,UNAVAILABLE,-
SecurityLeak,DEMO_SECRET,Pattern: SECRET,[REDACTED],REVIEW REQUIRED,Limit secret exposure in process environment; use secrets manager or IPC.
```

---

## 4. Automated Testing Methodology & Validation

Member 3 developed `tests/run_all_tests.sh`, a fully automated shell test harness containing **27 distinct tests** divided into 6 suites:

| Suite | Focus Area | Checks Performed | Result |
| :--- | :--- | :--- | :--- |
| **Suite 1** | Clean Compilation | `make clean && make all` with `-Wall -Wextra -std=c11 -pedantic`; binary existence | **5/5 PASS** |
| **Suite 2** | Member 1 Engine | Standalone `./auditor` (8/8 pass), `./inspector` unit checks (P, A, `--expect-empty`) | **4/4 PASS** |
| **Suite 3** | Member 2 Engine | Standalone `./member2` execution, dummy secret keyword detection | **2/2 PASS** |
| **Suite 4** | Integrated CLI | Flag dispatch (`--help`, `--version`, `--env-only`, `--ns-only`, `--sec-only`, `--pid 1`) | **6/6 PASS** |
| **Suite 5** | Structured Data | JSON syntax & schema validation, CSV RFC-4180 parsing, stdout stream isolation | **5/5 PASS** |
| **Suite 6** | Edge Cases & Errors | Non-numeric PID, negative PID, invalid flags, dead PID 99999999, stripped `env -i` | **5/5 PASS** |

**Summary**: 27/27 tests pass on clean runs.

---

## 5. Empirical Performance Evaluation & OS Analysis

All measurements were empirically gathered using `scripts/benchmark.py` and visualized using `scripts/generate_graphs.py`. **Zero data points were fabricated.**

### 5.1 Test Environment & Hardware Specification
- **Hardware Architecture**: x86_64
- **Operating System**: Linux under WSL2
- **Kernel**: Linux 6.18.54.1-microsoft-standard-WSL2
- **Python Runtime**: Python 3.14.4
- **C Compiler**: GCC with `-Wall -Wextra -std=c11 -pedantic -O2`
- **Timer Resolution**: Sub-microsecond monotonic clock (`time.perf_counter()`)

### 5.2 Latency Statistics (50 Repeated Full Trials)

| Metric | Measured Value (ms) |
| :--- | :--- |
| **Sample Size (Trials)** | 50 |
| **Mean Latency** | **6.05 ms** |
| **Median Latency** | 5.33 ms |
| **Standard Deviation** | ±1.65 ms |
| **Minimum Latency** | 4.48 ms |
| **Maximum Latency** | 12.22 ms |
| **95th Percentile (p95)** | 9.88 ms |

### 5.3 Subsystem Execution Breakdown (30 Trials Each)

| Subsystem / Pipeline Stage | Mean (ms) | Standard Deviation (ms) |
| :--- | :--- | :--- |
| **Process/Env Engine** | 4.98 | ±0.43 |
| **Namespace Inspector** | 0.84 | ±0.14 |
| **Security Scanner** | 0.78 | ±0.18 |
| **JSON Formatting** | 5.30 | ±0.66 |
| **CSV Formatting** | 5.15 | ±0.51 |
| **Full Unified Audit** | 6.74 | ±1.20 |

### 5.4 Environment Scaling Performance

| Variable Count | Mean Latency (ms) | Standard Deviation (ms) |
| :--- | :--- | :--- |
| **10 variables** | 1.01 | ±0.32 |
| **50 variables** | 1.19 | ±0.36 |
| **100 variables** | 1.02 | ±0.34 |
| **250 variables** | 1.09 | ±0.27 |
| **500 variables** | 1.42 | ±0.36 |
| **1000 variables** | 1.67 | ±0.19 |

### 5.5 Operating Systems Theoretical Analysis

1. **Process Lifecycle:** The Process/Env Engine recorded a mean of 4.98 ms, while the full unified audit recorded 6.74 ms in their respective component benchmark runs. These are separate measurements; they do not establish the percentage of total runtime attributable to process creation.

2. **Environment Scaling:** Scanning 1,000 variables recorded a mean of 1.67 ms in the tested environment. Intermediate measurements were not strictly monotonic, so additional controlled trials would be useful to establish the scaling trend.

3. **Structured Output:** JSON and CSV formatting recorded means of 5.30 ms and 5.15 ms respectively. A comparable text-output baseline is not available here, so the relative serialization overhead cannot be determined from these values alone.

4. **Measurement Context:** These results were collected under Linux on WSL2. Performance may vary with host load, software versions, and system configuration.

---

## 6. Limitations & Platform Portability

1. **Linux `/proc/[PID]/ns` Availability**:
   - On Linux systems, namespace links exist under `/proc/[PID]/ns/{pid,mnt,net,ipc,uts,user,cgroup,time}`.
   - On macOS (Darwin) or BSD systems, the `/proc` filesystem is absent. Member 3's engine gracefully records `UNAVAILABLE (No such file or directory)` without aborting execution.
2. **Namespace Isolation Semantics**:
   - Matching namespace IDs indicate membership in the same kernel resource table; differing IDs confirm distinct namespaces. However, identical IDs do not guarantee that no other security controls (e.g., Seccomp or AppArmor) are active.
3. **Keyword Heuristic Bounds**:
   - Pattern matching on variable names (`TOKEN`, `SECRET`, `PASSWORD`) detects convention-based exposures but may miss obfuscated keys (e.g., `VAR1=xyz`) or generate false positives for non-sensitive flags (`TOKEN_EXPIRY_SECONDS=300`).

---

## 7. Viva Questions & Discussion (Member 3 Focus)

1. **Q: How does `fork()` differ from `execve()` regarding environment variables?**  
   *A*: `fork()` creates an exact duplicate of the parent process, including copying the pointer table `environ` and its string buffers. `execve()` completely replaces the process image; the new image receives *only* the specific `char *const envp[]` array explicitly passed to `execve()`.

2. **Q: Why is passing `environ` directly to `execve()` considered dangerous in secure software?**  
   *A*: It leaks the entire parent environment—including API tokens, session cookies, database credentials, and path overrides—into child processes that may be untrusted or vulnerable. Clean array construction or `execle()` / `execve()` with sanitized arrays must be used.

3. **Q: How did Member 3 isolate stdout for `--format json` while Member 1's child printed console messages?**  
   *A*: When quiet mode or structured formats (`json`/`csv`) are active, the parent sets a quiet flag. Inside the child process after `fork()` but before `execve()`, `freopen("/dev/null", "w", stdout)` redirects stdout and stderr to the null device, ensuring the parent's stdout remains 100% parseable JSON/CSV.

4. **Q: What OS performance bottleneck was identified in the benchmark?**  
   *A*: Process lifecycle management (`fork()` + `execve()` + `waitpid()`). The Process/Env Engine recorded 4.98 ms and the 1,000-variable security scan recorded 1.67 ms in separate benchmark runs on Linux under WSL2.

5. **Q: How does the namespace auditor inspect other processes?**  
   *A*: It reads symbolic links under `/proc/[PID]/ns/` using the `readlink()` system call. The target link format (e.g., `net:[4026531992]`) contains the namespace type and unique kernel inode number.
