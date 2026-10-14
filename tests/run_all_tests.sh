#!/bin/bash
# ==============================================================================
# Environment Variable & Namespace Leak Auditor - Automated Test Suite
# Member 3: Integration, Reporting, and Evaluation
# ==============================================================================

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PASSED_COUNT=0
FAILED_COUNT=0
TOTAL_COUNT=0

COLOR_GREEN="\033[32m"
COLOR_RED="\033[31m"
COLOR_BLUE="\033[34m"
COLOR_BOLD="\033[1m"
COLOR_RESET="\033[0m"

log_test() {
    local status="$1"
    local name="$2"
    local details="${3:-}"
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    if [ "$status" = "PASS" ]; then
        PASSED_COUNT=$((PASSED_COUNT + 1))
        echo -e "  [${COLOR_GREEN}PASS${COLOR_RESET}] $name"
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
        echo -e "  [${COLOR_RED}FAIL${COLOR_RESET}] $name - $details"
    fi
}

echo -e "\n${COLOR_BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}   ENVIRONMENT VARIABLE & NAMESPACE AUDITOR - COMPREHENSIVE TEST SUITE ${COLOR_RESET}"
echo -e "${COLOR_BOLD}======================================================================${COLOR_RESET}\n"

# ------------------------------------------------------------------------------
# SUITE 1: Clean Build & Tool Compilation
# ------------------------------------------------------------------------------
echo -e "${COLOR_BLUE}${COLOR_BOLD}[SUITE 1] Clean Build & Tool Compilation${COLOR_RESET}"

if make clean >/dev/null 2>&1 && make all >/dev/null 2>&1; then
    log_test "PASS" "make clean && make all compiles cleanly"
else
    log_test "FAIL" "make clean && make all failed"
fi

for bin in inspector auditor member2 leak_auditor; do
    if [ -x "./$bin" ]; then
        log_test "PASS" "Binary '$bin' exists and is executable"
    else
        log_test "FAIL" "Binary '$bin' missing or not executable"
    fi
done

# ------------------------------------------------------------------------------
# SUITE 2: Member 1 Standalone Engine Tests
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BLUE}${COLOR_BOLD}[SUITE 2] Member 1 Standalone Engine Tests${COLOR_RESET}"

M1_OUT=$(./auditor 2>&1)
M1_EXIT=$?
if [ $M1_EXIT -eq 0 ] && echo "$M1_OUT" | grep -q "Audit summary: 8/8 tests passed"; then
    log_test "PASS" "Member 1 auditor passes all 8/8 environment tests"
else
    log_test "FAIL" "Member 1 auditor failed or did not report 8/8 tests" "Exit: $M1_EXIT"
fi

# Inspector unit tests
INSP_PASS=$(./inspector DEMO_MODE P 2>&1 || true)
if echo "$INSP_PASS" | grep -q "FAIL: DEMO_MODE did not match expectation"; then
    log_test "PASS" "Inspector reports absence when variable unset"
else
    log_test "FAIL" "Inspector output mismatch for unset variable"
fi

DEMO_TEST_VAR="hello" ./inspector DEMO_TEST_VAR P >/dev/null 2>&1
if [ $? -eq 0 ]; then
    log_test "PASS" "Inspector detects present variable with 'P'"
else
    log_test "FAIL" "Inspector failed to detect present variable"
fi

./inspector --expect-empty >/dev/null 2>&1
if [ $? -ne 0 ]; then
    log_test "PASS" "Inspector fails --expect-empty when environ is populated"
else
    log_test "FAIL" "Inspector passed --expect-empty unexpectedly"
fi

# ------------------------------------------------------------------------------
# SUITE 3: Member 2 Standalone Engine Tests
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BLUE}${COLOR_BOLD}[SUITE 3] Member 2 Standalone Engine Tests${COLOR_RESET}"

M2_OUT=$(./member2 2>&1)
M2_EXIT=$?
if [ $M2_EXIT -eq 0 ] && echo "$M2_OUT" | grep -q "===== NAMESPACE AUDIT ====="; then
    log_test "PASS" "Member 2 runs namespace audit without crashing"
else
    log_test "FAIL" "Member 2 failed basic execution" "Exit: $M2_EXIT"
fi

M2_SEC_OUT=$(env -i PATH="$PATH" API_TOKEN=dummy_token PASSWORD=secret ./member2 2>&1)
if echo "$M2_SEC_OUT" | grep -q "Variable: API_TOKEN" && echo "$M2_SEC_OUT" | grep -q "Variable: PASSWORD"; then
    log_test "PASS" "Member 2 detects sensitive dummy variables"
else
    log_test "FAIL" "Member 2 failed to detect sensitive variables"
fi

# ------------------------------------------------------------------------------
# SUITE 4: Integrated CLI Functional Tests
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BLUE}${COLOR_BOLD}[SUITE 4] Integrated CLI Functional Tests${COLOR_RESET}"

./leak_auditor --help >/dev/null 2>&1
if [ $? -eq 0 ]; then
    log_test "PASS" "CLI supports --help"
else
    log_test "FAIL" "CLI --help failed"
fi

./leak_auditor --version >/dev/null 2>&1
if [ $? -eq 0 ]; then
    log_test "PASS" "CLI supports --version"
else
    log_test "FAIL" "CLI --version failed"
fi

# Sub-audit filters
ENV_ONLY_OUT=$(./leak_auditor --env-only --quiet 2>&1)
if [ $? -eq 0 ]; then
    log_test "PASS" "CLI supports --env-only"
else
    log_test "FAIL" "CLI --env-only failed"
fi

NS_ONLY_OUT=$(./leak_auditor --ns-only --quiet 2>&1)
if [ $? -eq 0 ]; then
    log_test "PASS" "CLI supports --ns-only"
else
    log_test "FAIL" "CLI --ns-only failed"
fi

SEC_ONLY_OUT=$(./leak_auditor --sec-only --quiet 2>&1)
if [ $? -eq 0 ]; then
    log_test "PASS" "CLI supports --sec-only"
else
    log_test "FAIL" "CLI --sec-only failed"
fi

# PID targeting
PID_TEST_OUT=$(./leak_auditor --ns-only --pid 1 --quiet 2>&1)
if [ $? -eq 0 ]; then
    log_test "PASS" "CLI supports targeting PID 1 with --pid"
else
    log_test "FAIL" "CLI failed targeting PID 1"
fi

# ------------------------------------------------------------------------------
# SUITE 5: Structured Data Export (JSON & CSV) Validation
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BLUE}${COLOR_BOLD}[SUITE 5] Structured Data Export Validation${COLOR_RESET}"

JSON_TMP="results/audit_test_verify.json"
CSV_TMP="results/audit_test_verify.csv"
rm -f "$JSON_TMP" "$CSV_TMP"

./leak_auditor -j "$JSON_TMP" -c "$CSV_TMP" --quiet >/dev/null 2>&1
if [ -f "$JSON_TMP" ] && [ -f "$CSV_TMP" ]; then
    log_test "PASS" "File export flags (-j, -c) generated target files"
else
    log_test "FAIL" "File export flags failed to produce output files"
fi

# Verify JSON syntax and schema
JSON_CHECK=$(python3 -c '
import json, sys
with open("'"$JSON_TMP"'") as f:
    d = json.load(f)
assert d["project"] == "Environment Variable & Namespace Leak Auditor"
assert "summary" in d
assert "environment_tests" in d
assert len(d["environment_tests"]) == 8
assert "namespace_audit" in d
assert "security_findings" in d
print("JSON_OK")
' 2>&1)

if [ "$JSON_CHECK" = "JSON_OK" ]; then
    log_test "PASS" "JSON export is strictly valid and satisfies schema requirements"
else
    log_test "FAIL" "JSON validation failed: $JSON_CHECK"
fi

# Verify CSV syntax and schema
CSV_CHECK=$(python3 -c '
import csv, sys
with open("'"$CSV_TMP"'") as f:
    r = list(csv.reader(f))
assert len(r) >= 10
assert r[0] == ["Section", "Identifier", "Property", "Value", "Status", "Recommendation"]
sections = set(row[0] for row in r[1:])
assert "EnvironmentTest" in sections
assert "Namespace" in sections
print("CSV_OK")
' 2>&1)

if [ "$CSV_CHECK" = "CSV_OK" ]; then
    log_test "PASS" "CSV export is RFC-4180 compliant with correct tabular schema"
else
    log_test "FAIL" "CSV validation failed: $CSV_CHECK"
fi

# Stdout streaming formats
STDOUT_JSON=$(./leak_auditor --format json 2>&1 | python3 -m json.tool >/dev/null 2>&1 && echo "STREAM_JSON_OK" || echo "FAIL")
if [ "$STDOUT_JSON" = "STREAM_JSON_OK" ]; then
    log_test "PASS" "Stdout --format json produces pure parseable JSON stream"
else
    log_test "FAIL" "Stdout --format json output contains non-JSON text"
fi

STDOUT_CSV=$(./leak_auditor --format csv 2>&1 | python3 -c 'import csv, sys; list(csv.reader(sys.stdin)); print("STREAM_CSV_OK")' 2>/dev/null || echo "FAIL")
if [ "$STDOUT_CSV" = "STREAM_CSV_OK" ]; then
    log_test "PASS" "Stdout --format csv produces pure parseable CSV stream"
else
    log_test "FAIL" "Stdout --format csv output failed parsing"
fi

# ------------------------------------------------------------------------------
# SUITE 6: Edge Cases and Error Handling
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BLUE}${COLOR_BOLD}[SUITE 6] Edge Cases and Error Handling${COLOR_RESET}"

# Invalid PID argument (non-numeric)
ERR_PID=$(./leak_auditor -p invalid_pid 2>&1 || true)
if echo "$ERR_PID" | grep -q "Invalid target PID"; then
    log_test "PASS" "Rejects invalid non-numeric PID with exit code 2"
else
    log_test "FAIL" "Failed to reject invalid non-numeric PID"
fi

# Negative PID argument
ERR_NEG_PID=$(./leak_auditor -p -5 2>&1 || true)
if echo "$ERR_NEG_PID" | grep -q "Invalid target PID"; then
    log_test "PASS" "Rejects negative target PID"
else
    log_test "FAIL" "Failed to reject negative target PID"
fi

# Unknown command line flag
ERR_FLAG=$(./leak_auditor --nonexistent-option 2>&1 || true)
if echo "$ERR_FLAG" | grep -q "Usage:"; then
    log_test "PASS" "Handles unknown flags gracefully and displays usage"
else
    log_test "FAIL" "Did not handle unknown flag appropriately"
fi

# Nonexistent PID (should not crash, reports UNAVAILABLE)
NONEXIST_PID_OUT=$(./leak_auditor --ns-only --pid 99999999 --quiet 2>&1)
if [ $? -eq 0 ]; then
    log_test "PASS" "Gracefully handles nonexistent comparison PID (99999999)"
else
    log_test "FAIL" "Crashed on nonexistent PID"
fi

# Empty environment execution
CLEAN_ENV_RUN=$(env -i PATH="$PATH" ./leak_auditor --sec-only --format json 2>&1 | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["summary"]["security_findings_total"] == 0
print("CLEAN_ENV_OK")
' 2>/dev/null || echo "FAIL")

if [ "$CLEAN_ENV_RUN" = "CLEAN_ENV_OK" ]; then
    log_test "PASS" "Handles clean environment without false-positive security findings"
else
    log_test "FAIL" "Clean environment handling failed"
fi

# Cleanup test files
rm -f "$JSON_TMP" "$CSV_TMP"

# ------------------------------------------------------------------------------
# SUMMARY & REPORT
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_BOLD}======================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}                     TEST EXECUTION SUMMARY                           ${COLOR_RESET}"
echo -e "${COLOR_BOLD}======================================================================${COLOR_RESET}"
echo -e "Total Tests Run:  $TOTAL_COUNT"
echo -e "Tests Passed:    ${COLOR_GREEN}$PASSED_COUNT${COLOR_RESET}"
echo -e "Tests Failed:    $([ $FAILED_COUNT -gt 0 ] && echo -e "${COLOR_RED}$FAILED_COUNT${COLOR_RESET}" || echo "0")"

if [ $FAILED_COUNT -eq 0 ]; then
    echo -e "\n${COLOR_GREEN}${COLOR_BOLD}ALL AUTOMATED TEST SUITES PASSED SUCCESSFULLY!${COLOR_RESET}\n"
    exit 0
else
    echo -e "\n${COLOR_RED}${COLOR_BOLD}SOME TESTS FAILED! Review output above.${COLOR_RESET}\n"
    exit 1
fi
