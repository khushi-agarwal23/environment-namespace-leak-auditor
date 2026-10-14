#ifndef COMMON_H
#define COMMON_H

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>

#define MAX_TESTS 16
#define MAX_NAMESPACES 16
#define MAX_FINDINGS 128
#define STR_BUF_SMALL 64
#define STR_BUF_MED 256
#define STR_BUF_LARGE 512

/* Namespace status enum */
typedef enum {
    NS_STATUS_UNKNOWN = 0,
    NS_STATUS_SAME,
    NS_STATUS_DIFFERENT,
    NS_STATUS_UNAVAILABLE
} ns_status_t;

/* Environment test record */
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

/* Environment audit results */
typedef struct {
    pid_t parent_pid;
    int total_tests;
    int passed_tests;
    int failed_tests;
    env_test_record_t tests[MAX_TESTS];
} env_audit_results_t;

/* Single namespace inspection record */
typedef struct {
    char name[STR_BUF_SMALL];     /* pid, mnt, net, ipc, uts, user, cgroup, time */
    char self_ns[STR_BUF_MED];    /* e.g. pid:[4026532225] or empty */
    char target_ns[STR_BUF_MED];  /* comparison process target */
    ns_status_t status;
    char error_msg[STR_BUF_SMALL];
} ns_record_t;

/* Namespace audit results */
typedef struct {
    pid_t current_pid;
    pid_t target_pid;
    int total_namespaces;
    int same_count;
    int diff_count;
    int unavailable_count;
    ns_record_t records[MAX_NAMESPACES];
} ns_audit_results_t;

/* Security finding record */
typedef struct {
    char var_name[STR_BUF_MED];
    char redacted_value[STR_BUF_SMALL];
    char level[STR_BUF_SMALL];
    char recommendation[STR_BUF_MED];
    char matched_pattern[STR_BUF_SMALL];
} sec_finding_t;

/* Security audit results */
typedef struct {
    int total_scanned;
    int total_findings;
    sec_finding_t findings[MAX_FINDINGS];
} sec_audit_results_t;

/* Unified overall audit report */
typedef struct {
    char timestamp[STR_BUF_MED];
    char os_name[STR_BUF_MED];
    char kernel_version[STR_BUF_MED];
    bool has_env_results;
    bool has_ns_results;
    bool has_sec_results;
    env_audit_results_t env_results;
    ns_audit_results_t ns_results;
    sec_audit_results_t sec_results;
} audit_report_t;

/* Output format options */
typedef enum {
    FORMAT_TEXT = 0,
    FORMAT_JSON,
    FORMAT_CSV
} output_format_t;

/* CLI options */
typedef struct {
    bool run_env;
    bool run_ns;
    bool run_sec;
    pid_t target_pid;
    bool target_pid_set;
    output_format_t format;
    char json_file[STR_BUF_LARGE];
    char csv_file[STR_BUF_LARGE];
    bool verbose;
    bool quiet;
    bool color;
} cli_options_t;

#endif /* COMMON_H */
