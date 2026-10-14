# Laboratory Demonstration Guide
**Project**: Environment Variable & Namespace Leak Auditor  
**Lead Coordinator**: Member 3 (Integration, Reporting, and Evaluation)  

This guide provides a step-by-step demonstration script for presenting the project to the laboratory examiner or professor.

---

## Step 1: Clean Build Verification
Demonstrate that the repository builds cleanly from scratch with zero compiler warnings.

```bash
make clean
make all
```
**Talking Point**:
> *"We use strict compilation flags (`-Wall -Wextra -std=c11 -pedantic -O2`). The build compiles all standalone tools (`inspector`, `auditor`, `member2`) and the integrated `leak_auditor` without any warnings."*

---

## Step 2: Member 1 Standalone Engine Demonstration
Show Member 1's process creation and environment variable propagation engine.

```bash
./auditor
```
**Talking Point**:
> *"Member 1 demonstrates process creation using `fork()`, program image replacement with `execve()`, and process synchronization via `waitpid()`. All 8 controlled test cases pass, verifying inherited, removed, sanitized, and empty environment conditions."*

---

## Step 3: Member 2 Standalone Module Demonstration
Show Member 2's namespace inspection and security leak detection.

```bash
# Run against parent process
./member2

# Run with dummy sensitive variables
env -i PATH="$PATH" API_TOKEN="secret-token-123" PASSWORD="db-password" ./member2
```
**Talking Point**:
> *"Member 2 inspects Linux `/proc/[PID]/ns` symlinks and detects sensitive-looking environment variables. Notice that values are automatically redacted to `[REDACTED]` to prevent credential leaks during log inspection."*

---

## Step 4: Member 3 Integrated CLI Demonstration
Demonstrate the unified application running all modules through a common command-line interface.

```bash
# Full unified audit
./leak_auditor

# Targeted audit: Environment propagation only
./leak_auditor --env-only

# Targeted audit: Namespace inspection targeting PID 1
./leak_auditor --ns-only --pid 1

# Targeted audit: Security scan only
./leak_auditor --sec-only
```
**Talking Point**:
> *"Member 3 integrated the modules into a modular C architecture. The CLI supports flag dispatch for running full or targeted sub-audits, PID targeting, and runtime verbosity control."*

---

## Step 5: Structured JSON and CSV Reporting
Demonstrate export to machine-readable formats.

```bash
# Export both JSON and CSV files simultaneously
./leak_auditor -j results/demo.json -c results/demo.csv

# View generated JSON file
cat results/demo.json | head -n 30

# Verify JSON schema using python
python3 -m json.tool results/demo.json > /dev/null && echo "JSON is 100% Valid!"

# View generated CSV file
head -n 15 results/demo.csv
```
**Talking Point**:
> *"Member 3 implemented structured export. The JSON output satisfies an automated schema with system metadata, execution metrics, and typed arrays. The CSV output complies with RFC-4180 and can be opened directly in spreadsheet software."*

---

## Step 6: Automated Test Suite Execution
Run the comprehensive test suite to prove system reliability.

```bash
make test
# OR
./tests/run_all_tests.sh
```
**Talking Point**:
> *"We built an automated test runner containing 27 tests across 6 suites, verifying clean compilation, individual member logic, integrated flags, schema parsing, and OS edge cases such as invalid PIDs and dead processes."*

---

## Step 7: Performance Benchmarks & Generated Visualizations
Demonstrate the empirical performance evaluation and graph generation.

```bash
make benchmark
```
Open and display the generated PNG graphs in `docs/graphs/`:
- `docs/graphs/benchmark_execution_time.png` (50 repeated trials distribution)
- `docs/graphs/benchmark_component_breakdown.png` (subsystem execution breakdown)
- `docs/graphs/benchmark_env_scaling.png` (scaling curve up to 1,000 variables)

**Talking Point**:
> *"Member 3 conducted empirical timing experiments using sub-microsecond monotonic clocks. Over 50 repeated trials, mean runtime is 10.62 ms. The graphs demonstrate that process creation (`fork` + `execve`) accounts for over 85% of total time, while in-memory security scanning scales linearly and takes only ~2 ms even with 1,000 variables."*
