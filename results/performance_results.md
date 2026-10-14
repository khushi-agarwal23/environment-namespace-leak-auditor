# Empirical Performance Evaluation Report

**Project Title**: Environment Variable & Namespace Leak Auditor  
**Evaluation Lead**: Member 3 (Integration, Reporting, and Evaluation)  
**Measurement Date**: 2026-10-14 16:41:46  

## 1. Experimental Setup

- **Operating System**: Linux 6.18.54.1-microsoft-standard-WSL2 (x86_64)
- **Kernel/Architecture**: Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.43
- **Compiler**: GCC / Clang with `-Wall -Wextra -std=c11 -pedantic -O2`
- **Timing Method**: High-resolution monotonic clock (`time.perf_counter()`, sub-microsecond precision)
- **Operating System Context**: Process creation and address space allocation via `fork()`, image replacement via `execve()`, and process synchronization via `waitpid()`

## 2. Repeated Trials Latency (50 Iterations)

| Metric | Measured Value (ms) |
| :--- | :--- |
| **Sample Size (Trials)** | 50 |
| **Mean Latency** | **6.05 ms** |
| **Median Latency** | 5.33 ms |
| **Standard Deviation** | ±1.65 ms |
| **Minimum Latency** | 4.48 ms |
| **Maximum Latency** | 12.22 ms |
| **95th Percentile (p95)** | 9.88 ms |

## 3. Subsystem Execution Breakdown (30 Trials Each)

| Subsystem / Pipeline Stage | Mean (ms) | Median (ms) | Std Dev (ms) | Min (ms) | Max (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Process/Env Engine** | 4.98 | 4.87 | ±0.43 | 4.48 | 6.60 |
| **Namespace Inspector** | 0.84 | 0.81 | ±0.14 | 0.66 | 1.24 |
| **Security Scanner** | 0.78 | 0.73 | ±0.18 | 0.62 | 1.55 |
| **JSON Formatting** | 5.30 | 5.11 | ±0.66 | 4.59 | 7.14 |
| **CSV Formatting** | 5.15 | 5.03 | ±0.51 | 4.51 | 6.64 |
| **Full Unified Audit** | 6.74 | 6.48 | ±1.20 | 4.97 | 10.56 |

## 4. Environment Scaling Performance

| Variable Count | Mean Latency (ms) | Std Dev (ms) | Min (ms) | Max (ms) |
| :--- | :--- | :--- | :--- | :--- |
| **10 variables** | 1.01 | ±0.32 | 0.78 | 1.85 |
| **50 variables** | 1.19 | ±0.36 | 0.80 | 1.89 |
| **100 variables** | 1.02 | ±0.34 | 0.70 | 2.36 |
| **250 variables** | 1.09 | ±0.27 | 0.88 | 2.09 |
| **500 variables** | 1.42 | ±0.36 | 1.08 | 2.16 |
| **1000 variables** | 1.67 | ±0.19 | 1.42 | 2.04 |

## 5. Architectural Observations & OS Analysis

1. **Process and Environment Processing:** The Process/Env Engine recorded a mean execution time of 4.98 ms across 30 trials. Process creation with `fork()`, program replacement with `execve()`, and child-process synchronization with `waitpid()` are important operations in the environment-auditing workflow. Further profiling is needed to quantify the individual cost of each operation.

2. **Namespace Inspection and Security Scanning:** The Namespace Inspector recorded a mean of 0.84 ms, while the Security Scanner recorded a mean of 0.78 ms across 30 trials each. These measurements describe the tested WSL2 environment and workload; results may differ on other systems.

3. **Environment Size Scaling:** The measured mean latency increased from 1.01 ms for 10 environment variables to 1.67 ms for 1,000 variables. The intermediate measurements were not strictly monotonic, so additional repeated trials would help establish the scaling trend more reliably.

4. **Structured Output:** JSON formatting recorded a mean of 5.30 ms and CSV formatting recorded a mean of 5.15 ms. These are separate benchmark measurements; without a directly comparable text-output baseline, the relative overhead of structured formatting cannot be determined from these values alone.

5. **Measurement Limitations:** The benchmarks were conducted on Linux under WSL2 using the recorded software environment. The results provide an initial performance evaluation rather than a universal performance guarantee. Repeated measurements, controlled workloads, and finer-grained profiling would strengthen future evaluation.
