#define _POSIX_C_SOURCE 200809L
#include "ns_sec_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

extern char **environ;

static const char *NAMESPACE_TYPES[] = {
    "pid", "mnt", "net", "ipc",
    "uts", "user", "cgroup", "time"
};
#define NUM_NAMESPACE_TYPES 8

static const char *SENSITIVE_KEYWORDS[] = {
    "PASSWORD",
    "TOKEN",
    "SECRET",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    NULL
};

int is_sensitive_variable_name(const char *name, size_t len, char *matched_kw, size_t kw_buf_size) {
    if (!name || len == 0 || len >= STR_BUF_MED) return 0;

    char upper[STR_BUF_MED];
    for (size_t i = 0; i < len; i++) {
        upper[i] = (char)toupper((unsigned char)name[i]);
    }
    upper[len] = '\0';

    for (int i = 0; SENSITIVE_KEYWORDS[i] != NULL; i++) {
        if (strstr(upper, SENSITIVE_KEYWORDS[i]) != NULL) {
            if (matched_kw && kw_buf_size > 0) {
                snprintf(matched_kw, kw_buf_size, "%s", SENSITIVE_KEYWORDS[i]);
            }
            return 1;
        }
    }
    return 0;
}

int run_namespace_audit(pid_t target_pid, ns_audit_results_t *results, bool verbose, bool quiet) {
    if (!results) return -1;

    memset(results, 0, sizeof(*results));
    results->current_pid = getpid();
    results->target_pid = target_pid;
    results->total_namespaces = NUM_NAMESPACE_TYPES;

    if (!quiet) {
        printf("\n======================================================\n");
        printf("              LINUX NAMESPACE AUDITOR                 \n");
        printf("======================================================\n");
        printf("Current PID:   %ld\n", (long)results->current_pid);
        printf("Target PID:    %ld\n\n", (long)results->target_pid);
        printf("%-10s | %-12s | %-28s | %-28s\n",
               "Namespace", "Status", "Current Link", "Target Link");
        printf("------------------------------------------------------------------------------------\n");
    }

    char path1[STR_BUF_MED], path2[STR_BUF_MED];
    char link1[STR_BUF_MED], link2[STR_BUF_MED];

    for (int i = 0; i < NUM_NAMESPACE_TYPES; i++) {
        ns_record_t *rec = &results->records[i];
        snprintf(rec->name, sizeof(rec->name), "%s", NAMESPACE_TYPES[i]);

        snprintf(path1, sizeof(path1), "/proc/self/ns/%s", NAMESPACE_TYPES[i]);
        snprintf(path2, sizeof(path2), "/proc/%ld/ns/%s", (long)target_pid, NAMESPACE_TYPES[i]);

        ssize_t x = readlink(path1, link1, sizeof(link1) - 1);
        int err1 = errno;
        ssize_t y = readlink(path2, link2, sizeof(link2) - 1);
        int err2 = errno;

        if (x < 0 || y < 0) {
            rec->status = NS_STATUS_UNAVAILABLE;
            results->unavailable_count++;
            const char *err_str = strerror(x < 0 ? err1 : err2);
            snprintf(rec->error_msg, sizeof(rec->error_msg), "%s", err_str);
            snprintf(rec->self_ns, sizeof(rec->self_ns), "N/A");
            snprintf(rec->target_ns, sizeof(rec->target_ns), "N/A");

            if (!quiet) {
                printf("%-10s | %-12s | %-28s | %-28s\n",
                       rec->name, "UNAVAILABLE", rec->error_msg, "-");
            }
        } else {
            link1[x] = '\0';
            link2[y] = '\0';
            snprintf(rec->self_ns, sizeof(rec->self_ns), "%s", link1);
            snprintf(rec->target_ns, sizeof(rec->target_ns), "%s", link2);

            if (strcmp(link1, link2) == 0) {
                rec->status = NS_STATUS_SAME;
                results->same_count++;
                if (!quiet) {
                    printf("%-10s | %-12s | %-28s | %-28s\n",
                           rec->name, "SAME", rec->self_ns, rec->target_ns);
                }
            } else {
                rec->status = NS_STATUS_DIFFERENT;
                results->diff_count++;
                if (!quiet) {
                    printf("%-10s | %-12s | %-28s | %-28s\n",
                           rec->name, "DIFFERENT", rec->self_ns, rec->target_ns);
                }
            }
        }
    }

    if (!quiet) {
        printf("------------------------------------------------------------------------------------\n");
        printf("Namespace Summary: Total: %d, Matching: %d, Different: %d, Unavailable: %d\n",
               results->total_namespaces, results->same_count,
               results->diff_count, results->unavailable_count);
        if (verbose && results->unavailable_count > 0) {
            printf("Note: Unavailable namespaces indicate /proc/[PID]/ns is unsupported on this OS\n"
                   "      or restricted by process permissions.\n");
        }
    }

    return 0;
}

int run_security_audit(sec_audit_results_t *results, bool verbose, bool quiet) {
    if (!results) return -1;

    memset(results, 0, sizeof(*results));

    if (!quiet) {
        printf("\n======================================================\n");
        printf("             SECURITY & EXPOSURE AUDITOR              \n");
        printf("======================================================\n");
    }

    for (char **p = environ; p != NULL && *p != NULL; p++) {
        results->total_scanned++;

        char *eq = strchr(*p, '=');
        if (!eq) continue;

        size_t name_len = (size_t)(eq - *p);
        if (name_len == 0 || name_len >= STR_BUF_MED) continue;

        char var_name[STR_BUF_MED];
        memcpy(var_name, *p, name_len);
        var_name[name_len] = '\0';

        char matched_kw[STR_BUF_SMALL] = {0};
        if (is_sensitive_variable_name(var_name, name_len, matched_kw, sizeof(matched_kw))) {
            if (results->total_findings < MAX_FINDINGS) {
                sec_finding_t *f = &results->findings[results->total_findings];
                snprintf(f->var_name, sizeof(f->var_name), "%s", var_name);
                snprintf(f->redacted_value, sizeof(f->redacted_value), "[REDACTED]");
                snprintf(f->level, sizeof(f->level), "REVIEW REQUIRED");
                snprintf(f->recommendation, sizeof(f->recommendation),
                         "Limit secret exposure in process environment; use secrets manager or IPC.");
                snprintf(f->matched_pattern, sizeof(f->matched_pattern), "%s", matched_kw);
                results->total_findings++;

                if (!quiet) {
                    printf("[!] SENSITIVE EXPOSURE DETECTED:\n");
                    printf("    Variable:       %s\n", f->var_name);
                    printf("    Pattern Match:  %s\n", f->matched_pattern);
                    printf("    Value:          %s\n", f->redacted_value);
                    printf("    Risk Level:     %s\n", f->level);
                    printf("    Recommendation: %s\n\n", f->recommendation);
                }
            }
        } else if (verbose && !quiet) {
            printf("    [Clean] %s\n", var_name);
        }
    }

    if (!quiet) {
        printf("Security Audit Summary: %d variables scanned, %d finding(s) detected.\n",
               results->total_scanned, results->total_findings);
        if (results->total_findings == 0) {
            printf("No sensitive-looking variables detected in active environment.\n");
        }
    }

    return results->total_findings;
}
