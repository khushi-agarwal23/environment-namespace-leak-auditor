# Empirical Performance Evaluation Report

**Project Title**: Environment Variable & Namespace Leak Auditor  
**Evaluation Lead**: Member 3 (Integration, Reporting, and Evaluation)  
**Measurement Date**: 2026-10-14 13:24:56  

## 1. Experimental Setup

- **Operating System**: Darwin 24.6.0 (arm64)
- **Kernel/Architecture**: macOS-15.7.4-arm64-arm-64bit-Mach-O
- **Compiler**: GCC / Clang with `-Wall -Wextra -std=c11 -pedantic -O2`
- **Timing Method**: High-resolution monotonic clock (`time.perf_counter()`, sub-microsecond precision)
- **Operating System Context**: Process creation and address space allocation via `fork()`, image replacement via `execve()`, and process synchronization via `waitpid()`

## 2. Repeated Trials Latency (50 Iterations)

| Metric | Measured Value (ms) |
| :--- | :--- |
| **Sample Size (Trials)** | 50 |
| **Mean Latency** | **10.79 ms** |
| **Median Latency** | 10.71 ms |
| **Standard Deviation** | ±0.38 ms |
| **Minimum Latency** | 10.41 ms |
| **Maximum Latency** | 12.93 ms |
| **95th Percentile (p95)** | 11.23 ms |

## 3. Subsystem Execution Breakdown (30 Trials Each)

| Subsystem / Pipeline Stage | Mean (ms) | Median (ms) | Std Dev (ms) | Min (ms) | Max (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Process/Env Engine** | 10.70 | 10.69 | ±0.29 | 10.11 | 11.35 |
| **Namespace Inspector** | 1.80 | 1.66 | ±0.52 | 1.59 | 4.45 |
| **Security Scanner** | 1.68 | 1.64 | ±0.11 | 1.56 | 1.97 |
| **JSON Formatting** | 10.76 | 10.74 | ±0.21 | 10.46 | 11.51 |
| **CSV Formatting** | 10.68 | 10.63 | ±0.24 | 10.41 | 11.63 |
| **Full Unified Audit** | 10.74 | 10.71 | ±0.26 | 10.26 | 11.45 |

## 4. Environment Scaling Performance

| Variable Count | Mean Latency (ms) | Std Dev (ms) | Min (ms) | Max (ms) |
| :--- | :--- | :--- | :--- | :--- |
| **10 variables** | 2.38 | ±1.22 | 1.61 | 4.98 |
| **50 variables** | 1.82 | ±0.17 | 1.62 | 2.21 |
| **100 variables** | 1.80 | ±0.11 | 1.67 | 2.08 |
| **250 variables** | 1.85 | ±0.10 | 1.73 | 2.04 |
| **500 variables** | 2.03 | ±0.15 | 1.87 | 2.45 |
| **1000 variables** | 2.25 | ±0.11 | 2.09 | 2.51 |

## 5. Architectural Observations & OS Analysis

1. **Process Creation Cost Dominance**: Over 85% of total execution time in the complete audit is spent within `fork()` and `execve()`. Each test requires creating a new process control block (PCB), duplicating or copy-on-write sharing page tables, wiping virtual memory during `execve()`, and scheduling child execution.
2. **In-Memory Subsystem Efficiency**: Namespace path inspection and security substring scanning operate at microsecond scale per entity. Even when scaling to 1,000 environment variables, the security scan completes within a single-digit millisecond timeframe.
3. **Formatting Overhead**: Structured JSON and CSV serialization overhead is negligible (< 1 ms difference compared to text mode), demonstrating that streaming data structures in memory is computationally trivial compared to OS kernel context switches.
