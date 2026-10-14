#define _POSIX_C_SOURCE 200809L
#include "reporter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>

void init_audit_report(audit_report_t *report) {
    if (!report) return;
    memset(report, 0, sizeof(*report));

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        strftime(report->timestamp, sizeof(report->timestamp), "%Y-%m-%dT%H:%M:%S%z", tm_info);
    } else {
        snprintf(report->timestamp, sizeof(report->timestamp), "UNKNOWN");
    }

    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(report->os_name, sizeof(report->os_name), "%s %s", u.sysname, u.machine);
        snprintf(report->kernel_version, sizeof(report->kernel_version), "%s", u.release);
    } else {
        snprintf(report->os_name, sizeof(report->os_name), "Generic POSIX");
        snprintf(report->kernel_version, sizeof(report->kernel_version), "Unknown");
    }
}

static void escape_json_string(const char *in, char *out, size_t out_size) {
    if (!in || !out || out_size == 0) return;
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0' && o + 2 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') {
            out[o++] = '\\';
            out[o++] = '"';
        } else if (c == '\\') {
            out[o++] = '\\';
            out[o++] = '\\';
        } else if (c == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c == '\r') {
            out[o++] = '\\';
            out[o++] = 'r';
        } else if (c == '\t') {
            out[o++] = '\\';
            out[o++] = 't';
        } else if (c < 32) {
            /* ignore control chars */
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

static const char *ns_status_to_string(ns_status_t status) {
    switch (status) {
        case NS_STATUS_SAME: return "SAME";
        case NS_STATUS_DIFFERENT: return "DIFFERENT";
        case NS_STATUS_UNAVAILABLE: return "UNAVAILABLE";
        default: return "UNKNOWN";
    }
}

void print_report_text(const audit_report_t *report, FILE *stream, bool verbose, bool color) {
    if (!report || !stream) return;

    const char *c_reset = color ? "\033[0m" : "";
    const char *c_bold  = color ? "\033[1m" : "";
    const char *c_green = color ? "\033[32m" : "";
    const char *c_red   = color ? "\033[31m" : "";
    const char *c_yellow= color ? "\033[33m" : "";
    const char *c_cyan  = color ? "\033[36m" : "";

    fprintf(stream, "\n%s======================================================================%s\n", c_bold, c_reset);
    fprintf(stream, "%s           ENVIRONMENT VARIABLE & NAMESPACE AUDITOR REPORT           %s\n", c_bold, c_reset);
    fprintf(stream, "%s======================================================================%s\n", c_bold, c_reset);
    fprintf(stream, "Timestamp: %s\n", report->timestamp);
    fprintf(stream, "OS:        %s (Kernel: %s)\n", report->os_name, report->kernel_version);
    fprintf(stream, "PID:       %ld\n\n", (long)getpid());

    if (report->has_env_results) {
        fprintf(stream, "%s--- Process & Environment Propagation Engine ---%s\n", c_cyan, c_reset);
        for (int i = 0; i < report->env_results.total_tests; i++) {
            const env_test_record_t *t = &report->env_results.tests[i];
            fprintf(stream, "  [Test %d] %-34s : %s%s%s (Exit: %d)\n",
                    t->test_id, t->name,
                    t->passed ? c_green : c_red,
                    t->passed ? "PASS" : "FAIL",
                    c_reset, t->actual_exit);
            if (verbose) {
                fprintf(stream, "            Target: %s | Expect: %s | Note: %s\n",
                        t->target_var, t->expectation, t->details);
            }
        }
        fprintf(stream, "  Summary: %d/%d Passed (%d Failed)\n\n",
                report->env_results.passed_tests, report->env_results.total_tests,
                report->env_results.failed_tests);
    }

    if (report->has_ns_results) {
        fprintf(stream, "%s--- Linux Namespace Inspection ---%s\n", c_cyan, c_reset);
        fprintf(stream, "  Compared with Target PID: %ld\n", (long)report->ns_results.target_pid);
        fprintf(stream, "  %-10s | %-12s | %-24s | %-24s\n", "Type", "Status", "Current Link", "Target Link");
        fprintf(stream, "  ------------------------------------------------------------------------\n");
        for (int i = 0; i < report->ns_results.total_namespaces; i++) {
            const ns_record_t *ns = &report->ns_results.records[i];
            const char *st_col = (ns->status == NS_STATUS_SAME) ? c_green :
                                 (ns->status == NS_STATUS_DIFFERENT) ? c_yellow : c_reset;
            fprintf(stream, "  %-10s | %s%-12s%s | %-24s | %-24s\n",
                    ns->name, st_col, ns_status_to_string(ns->status), c_reset,
                    ns->self_ns, ns->target_ns);
        }
        fprintf(stream, "  Summary: %d Total (Matching: %d, Different: %d, Unavailable: %d)\n\n",
                report->ns_results.total_namespaces, report->ns_results.same_count,
                report->ns_results.diff_count, report->ns_results.unavailable_count);
    }

    if (report->has_sec_results) {
        fprintf(stream, "%s--- Security & Leak Exposure Audit ---%s\n", c_cyan, c_reset);
        fprintf(stream, "  Variables Scanned: %d | Sensitive Findings: %d\n",
                report->sec_results.total_scanned, report->sec_results.total_findings);
        for (int i = 0; i < report->sec_results.total_findings; i++) {
            const sec_finding_t *f = &report->sec_results.findings[i];
            fprintf(stream, "  %s[!] Finding %d: %s%s (Pattern: %s)\n",
                    c_yellow, i + 1, f->var_name, c_reset, f->matched_pattern);
            fprintf(stream, "      Value:          %s\n", f->redacted_value);
            fprintf(stream, "      Level:          %s\n", f->level);
            fprintf(stream, "      Recommendation: %s\n", f->recommendation);
        }
        if (report->sec_results.total_findings == 0) {
            fprintf(stream, "  %s[OK] No sensitive environment variables exposed.%s\n", c_green, c_reset);
        }
        fprintf(stream, "\n");
    }

    fprintf(stream, "%s======================================================================%s\n\n", c_bold, c_reset);
}

int export_report_json(const audit_report_t *report, FILE *stream) {
    if (!report || !stream) return -1;

    char esc_os[STR_BUF_MED];
    char esc_kernel[STR_BUF_MED];
    escape_json_string(report->os_name, esc_os, sizeof(esc_os));
    escape_json_string(report->kernel_version, esc_kernel, sizeof(esc_kernel));

    fprintf(stream, "{\n");
    fprintf(stream, "  \"project\": \"Environment Variable & Namespace Leak Auditor\",\n");
    fprintf(stream, "  \"schema_version\": \"1.0.0\",\n");
    fprintf(stream, "  \"timestamp\": \"%s\",\n", report->timestamp);
    fprintf(stream, "  \"system\": {\n");
    fprintf(stream, "    \"os\": \"%s\",\n", esc_os);
    fprintf(stream, "    \"kernel\": \"%s\",\n", esc_kernel);
    fprintf(stream, "    \"auditor_pid\": %ld\n", (long)getpid());
    fprintf(stream, "  },\n");

    /* Summary */
    fprintf(stream, "  \"summary\": {\n");
    int env_total = report->has_env_results ? report->env_results.total_tests : 0;
    int env_pass  = report->has_env_results ? report->env_results.passed_tests : 0;
    int env_fail  = report->has_env_results ? report->env_results.failed_tests : 0;
    int ns_total  = report->has_ns_results  ? report->ns_results.total_namespaces : 0;
    int ns_same   = report->has_ns_results  ? report->ns_results.same_count : 0;
    int ns_diff   = report->has_ns_results  ? report->ns_results.diff_count : 0;
    int ns_unavail= report->has_ns_results  ? report->ns_results.unavailable_count : 0;
    int sec_scanned = report->has_sec_results ? report->sec_results.total_scanned : 0;
    int sec_findings = report->has_sec_results ? report->sec_results.total_findings : 0;

    fprintf(stream, "    \"environment_tests_total\": %d,\n", env_total);
    fprintf(stream, "    \"environment_tests_passed\": %d,\n", env_pass);
    fprintf(stream, "    \"environment_tests_failed\": %d,\n", env_fail);
    fprintf(stream, "    \"namespaces_total\": %d,\n", ns_total);
    fprintf(stream, "    \"namespaces_matching\": %d,\n", ns_same);
    fprintf(stream, "    \"namespaces_different\": %d,\n", ns_diff);
    fprintf(stream, "    \"namespaces_unavailable\": %d,\n", ns_unavail);
    fprintf(stream, "    \"environment_variables_scanned\": %d,\n", sec_scanned);
    fprintf(stream, "    \"security_findings_total\": %d\n", sec_findings);
    fprintf(stream, "  }");

    /* Environment Tests Array */
    if (report->has_env_results) {
        fprintf(stream, ",\n  \"environment_tests\": [\n");
        for (int i = 0; i < report->env_results.total_tests; i++) {
            const env_test_record_t *t = &report->env_results.tests[i];
            char esc_name[STR_BUF_MED], esc_desc[STR_BUF_MED], esc_dtl[STR_BUF_MED];
            escape_json_string(t->name, esc_name, sizeof(esc_name));
            escape_json_string(t->description, esc_desc, sizeof(esc_desc));
            escape_json_string(t->details, esc_dtl, sizeof(esc_dtl));

            fprintf(stream, "    {\n");
            fprintf(stream, "      \"test_id\": %d,\n", t->test_id);
            fprintf(stream, "      \"name\": \"%s\",\n", esc_name);
            fprintf(stream, "      \"description\": \"%s\",\n", esc_desc);
            fprintf(stream, "      \"target_variable\": \"%s\",\n", t->target_var);
            fprintf(stream, "      \"expectation\": \"%s\",\n", t->expectation);
            fprintf(stream, "      \"expected_exit\": %d,\n", t->expected_exit);
            fprintf(stream, "      \"actual_exit\": %d,\n", t->actual_exit);
            fprintf(stream, "      \"status\": \"%s\",\n", t->passed ? "PASS" : "FAIL");
            fprintf(stream, "      \"details\": \"%s\"\n", esc_dtl);
            fprintf(stream, "    }%s\n", (i + 1 < report->env_results.total_tests) ? "," : "");
        }
        fprintf(stream, "  ]");
    }

    /* Namespaces Array */
    if (report->has_ns_results) {
        fprintf(stream, ",\n  \"namespace_audit\": {\n");
        fprintf(stream, "    \"target_pid\": %ld,\n", (long)report->ns_results.target_pid);
        fprintf(stream, "    \"current_pid\": %ld,\n", (long)report->ns_results.current_pid);
        fprintf(stream, "    \"inspections\": [\n");
        for (int i = 0; i < report->ns_results.total_namespaces; i++) {
            const ns_record_t *ns = &report->ns_results.records[i];
            char esc_self[STR_BUF_MED], esc_tgt[STR_BUF_MED], esc_err[STR_BUF_MED];
            escape_json_string(ns->self_ns, esc_self, sizeof(esc_self));
            escape_json_string(ns->target_ns, esc_tgt, sizeof(esc_tgt));
            escape_json_string(ns->error_msg, esc_err, sizeof(esc_err));

            fprintf(stream, "      {\n");
            fprintf(stream, "        \"namespace\": \"%s\",\n", ns->name);
            fprintf(stream, "        \"status\": \"%s\",\n", ns_status_to_string(ns->status));
            fprintf(stream, "        \"self_link\": \"%s\",\n", esc_self);
            fprintf(stream, "        \"target_link\": \"%s\",\n", esc_tgt);
            fprintf(stream, "        \"error\": \"%s\"\n", esc_err);
            fprintf(stream, "      }%s\n", (i + 1 < report->ns_results.total_namespaces) ? "," : "");
        }
        fprintf(stream, "    ]\n  }");
    }

    /* Security Findings Array */
    if (report->has_sec_results) {
        fprintf(stream, ",\n  \"security_findings\": [\n");
        for (int i = 0; i < report->sec_results.total_findings; i++) {
            const sec_finding_t *f = &report->sec_results.findings[i];
            char esc_var[STR_BUF_MED], esc_rec[STR_BUF_MED];
            escape_json_string(f->var_name, esc_var, sizeof(esc_var));
            escape_json_string(f->recommendation, esc_rec, sizeof(esc_rec));

            fprintf(stream, "    {\n");
            fprintf(stream, "      \"variable\": \"%s\",\n", esc_var);
            fprintf(stream, "      \"matched_pattern\": \"%s\",\n", f->matched_pattern);
            fprintf(stream, "      \"value\": \"%s\",\n", f->redacted_value);
            fprintf(stream, "      \"risk_level\": \"%s\",\n", f->level);
            fprintf(stream, "      \"recommendation\": \"%s\"\n", esc_rec);
            fprintf(stream, "    }%s\n", (i + 1 < report->sec_results.total_findings) ? "," : "");
        }
        fprintf(stream, "  ]");
    }

    fprintf(stream, "\n}\n");
    return 0;
}

int save_report_json(const audit_report_t *report, const char *filepath) {
    if (!report || !filepath) return -1;
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("fopen json");
        return -1;
    }
    int res = export_report_json(report, fp);
    fclose(fp);
    return res;
}

static void escape_csv_field(const char *in, char *out, size_t out_size) {
    if (!in || !out || out_size == 0) return;
    bool needs_quotes = false;
    for (size_t i = 0; in[i]; i++) {
        if (in[i] == ',' || in[i] == '"' || in[i] == '\n' || in[i] == '\r') {
            needs_quotes = true;
            break;
        }
    }

    if (!needs_quotes) {
        snprintf(out, out_size, "%s", in);
        return;
    }

    size_t o = 0;
    out[o++] = '"';
    for (size_t i = 0; in[i] && o + 3 < out_size; i++) {
        if (in[i] == '"') {
            out[o++] = '"';
            out[o++] = '"';
        } else {
            out[o++] = in[i];
        }
    }
    out[o++] = '"';
    out[o] = '\0';
}

int export_report_csv(const audit_report_t *report, FILE *stream) {
    if (!report || !stream) return -1;

    fprintf(stream, "Section,Identifier,Property,Value,Status,Recommendation\n");

    /* Metadata rows */
    char esc_buf[STR_BUF_MED];
    escape_csv_field(report->timestamp, esc_buf, sizeof(esc_buf));
    fprintf(stream, "Metadata,Header,Timestamp,%s,INFO,-\n", esc_buf);
    escape_csv_field(report->os_name, esc_buf, sizeof(esc_buf));
    fprintf(stream, "Metadata,Header,OS,%s,INFO,-\n", esc_buf);
    escape_csv_field(report->kernel_version, esc_buf, sizeof(esc_buf));
    fprintf(stream, "Metadata,Header,Kernel,%s,INFO,-\n", esc_buf);

    /* Environment Tests */
    if (report->has_env_results) {
        for (int i = 0; i < report->env_results.total_tests; i++) {
            const env_test_record_t *t = &report->env_results.tests[i];
            char esc_name[STR_BUF_MED], esc_dtl[STR_BUF_MED];
            escape_csv_field(t->name, esc_name, sizeof(esc_name));
            escape_csv_field(t->details, esc_dtl, sizeof(esc_dtl));
            fprintf(stream, "EnvironmentTest,TEST_%d,%s,%s,%s,-\n",
                    t->test_id, esc_name, esc_dtl, t->passed ? "PASS" : "FAIL");
        }
    }

    /* Namespaces */
    if (report->has_ns_results) {
        for (int i = 0; i < report->ns_results.total_namespaces; i++) {
            const ns_record_t *ns = &report->ns_results.records[i];
            char val_buf[STR_BUF_MED], esc_val[STR_BUF_MED];
            snprintf(val_buf, sizeof(val_buf), "Self: %s | Target: %s", ns->self_ns, ns->target_ns);
            escape_csv_field(val_buf, esc_val, sizeof(esc_val));
            fprintf(stream, "Namespace,%s,LinkComparison,%s,%s,-\n",
                    ns->name, esc_val, ns_status_to_string(ns->status));
        }
    }

    /* Security Findings */
    if (report->has_sec_results) {
        for (int i = 0; i < report->sec_results.total_findings; i++) {
            const sec_finding_t *f = &report->sec_results.findings[i];
            char esc_var[STR_BUF_MED], esc_rec[STR_BUF_MED];
            escape_csv_field(f->var_name, esc_var, sizeof(esc_var));
            escape_csv_field(f->recommendation, esc_rec, sizeof(esc_rec));
            fprintf(stream, "SecurityLeak,%s,Pattern: %s,%s,%s,%s\n",
                    esc_var, f->matched_pattern, f->redacted_value, f->level, esc_rec);
        }
    }

    return 0;
}

int save_report_csv(const audit_report_t *report, const char *filepath) {
    if (!report || !filepath) return -1;
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("fopen csv");
        return -1;
    }
    int res = export_report_csv(report, fp);
    fclose(fp);
    return res;
}
