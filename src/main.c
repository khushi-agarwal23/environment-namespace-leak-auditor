#define _POSIX_C_SOURCE 200809L
#include "common.h"
#include "env_engine.h"
#include "ns_sec_engine.h"
#include "reporter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>

#define TOOL_NAME "leak_auditor"
#define TOOL_VERSION "1.0.0"

static void print_usage(const char *prog_name) {
    printf("Environment Variable & Namespace Leak Auditor (v%s)\n", TOOL_VERSION);
    printf("Operating Systems Lab Project - Unified Audit Engine\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Audit Selection:\n");
    printf("  -a, --all               Run all audits (Environment, Namespace, Security) [Default]\n");
    printf("  -e, --env-only          Run only the Process & Environment Propagation Engine\n");
    printf("  -n, --ns-only           Run only the Linux Namespace Inspection Audit\n");
    printf("  -s, --sec-only          Run only the Sensitive Environment Variable Leak Audit\n\n");
    printf("Parameters:\n");
    printf("  -p, --pid <PID>         Target process PID for namespace comparison (default: parent PID)\n\n");
    printf("Output & Reporting:\n");
    printf("  -f, --format <FMT>      Stdout format: text, json, or csv (default: text)\n");
    printf("  -j, --json-out <FILE>   Export structured JSON report to FILE\n");
    printf("  -c, --csv-out <FILE>    Export structured CSV report to FILE\n");
    printf("  -v, --verbose           Enable verbose diagnostic details\n");
    printf("  -q, --quiet             Quiet mode: suppress runtime banners, output format only\n");
    printf("      --no-color          Disable ANSI color formatting in terminal output\n");
    printf("  -h, --help              Display this help menu and exit\n");
    printf("      --version           Display version information and exit\n\n");
    printf("Examples:\n");
    printf("  %s                      Run comprehensive audit and display report\n", prog_name);
    printf("  %s --env-only           Run only process environment propagation tests\n", prog_name);
    printf("  %s --ns-only --pid 1    Compare current namespaces with PID 1\n", prog_name);
    printf("  %s --format json        Emit structured JSON to stdout for pipeline ingestion\n", prog_name);
    printf("  %s -j audit.json -c audit.csv  Run full audit and export both JSON and CSV\n", prog_name);
}

int main(int argc, char *argv[]) {
    cli_options_t options;
    memset(&options, 0, sizeof(options));
    options.target_pid = getppid();
    options.format = FORMAT_TEXT;
    options.color = isatty(fileno(stdout));

    static struct option long_options[] = {
        {"all",        no_argument,       NULL, 'a'},
        {"env-only",   no_argument,       NULL, 'e'},
        {"ns-only",    no_argument,       NULL, 'n'},
        {"sec-only",   no_argument,       NULL, 's'},
        {"pid",        required_argument, NULL, 'p'},
        {"format",     required_argument, NULL, 'f'},
        {"json-out",   required_argument, NULL, 'j'},
        {"csv-out",    required_argument, NULL, 'c'},
        {"verbose",    no_argument,       NULL, 'v'},
        {"quiet",      no_argument,       NULL, 'q'},
        {"no-color",   no_argument,       NULL, 1001},
        {"version",    no_argument,       NULL, 1002},
        {"help",       no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    int opt_index = 0;
    while ((opt = getopt_long(argc, argv, "aensp:f:j:c:vqh", long_options, &opt_index)) != -1) {
        switch (opt) {
            case 'a':
                options.run_env = true;
                options.run_ns = true;
                options.run_sec = true;
                break;
            case 'e':
                options.run_env = true;
                break;
            case 'n':
                options.run_ns = true;
                break;
            case 's':
                options.run_sec = true;
                break;
            case 'p': {
                char *endptr = NULL;
                errno = 0;
                long p = strtol(optarg, &endptr, 10);
                if (errno != 0 || *endptr != '\0' || p <= 0 || p > INT_MAX) {
                    fprintf(stderr, "Error: Invalid target PID '%s'. Must be a positive integer.\n", optarg);
                    return 2;
                }
                options.target_pid = (pid_t)p;
                options.target_pid_set = true;
                break;
            }
            case 'f':
                if (strcasecmp(optarg, "json") == 0) {
                    options.format = FORMAT_JSON;
                } else if (strcasecmp(optarg, "csv") == 0) {
                    options.format = FORMAT_CSV;
                } else if (strcasecmp(optarg, "text") == 0) {
                    options.format = FORMAT_TEXT;
                } else {
                    fprintf(stderr, "Error: Unknown format '%s'. Choose text, json, or csv.\n", optarg);
                    return 2;
                }
                break;
            case 'j':
                snprintf(options.json_file, sizeof(options.json_file), "%s", optarg);
                break;
            case 'c':
                snprintf(options.csv_file, sizeof(options.csv_file), "%s", optarg);
                break;
            case 'v':
                options.verbose = true;
                break;
            case 'q':
                options.quiet = true;
                break;
            case 1001:
                options.color = false;
                break;
            case 1002:
                printf("%s version %s (OS Lab Member 3 Unified Engine)\n", TOOL_NAME, TOOL_VERSION);
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 2;
        }
    }

    /* If no specific audit requested, run all by default */
    if (!options.run_env && !options.run_ns && !options.run_sec) {
        options.run_env = true;
        options.run_ns = true;
        options.run_sec = true;
    }

    /* If format is json or csv on stdout, suppress interactive streaming logs */
    bool stdout_streaming_quiet = options.quiet || (options.format != FORMAT_TEXT);

    audit_report_t report;
    init_audit_report(&report);

    int exit_code = 0;

    /* 1. Environment Engine */
    if (options.run_env) {
        report.has_env_results = true;
        int failed = run_environment_audit(&report.env_results, options.verbose, stdout_streaming_quiet);
        if (failed > 0) {
            exit_code = 1;
        }
    }

    /* 2. Namespace Engine */
    if (options.run_ns) {
        report.has_ns_results = true;
        run_namespace_audit(options.target_pid, &report.ns_results, options.verbose, stdout_streaming_quiet);
    }

    /* 3. Security Engine */
    if (options.run_sec) {
        report.has_sec_results = true;
        run_security_audit(&report.sec_results, options.verbose, stdout_streaming_quiet);
    }

    /* Output to stdout based on selected format */
    if (options.format == FORMAT_TEXT) {
        if (!options.quiet) {
            print_report_text(&report, stdout, options.verbose, options.color);
        }
    } else if (options.format == FORMAT_JSON) {
        export_report_json(&report, stdout);
    } else if (options.format == FORMAT_CSV) {
        export_report_csv(&report, stdout);
    }

    /* File Exports */
    if (options.json_file[0] != '\0') {
        if (save_report_json(&report, options.json_file) == 0) {
            if (!options.quiet && options.format == FORMAT_TEXT) {
                printf("[✓] Exported structured JSON report to: %s\n", options.json_file);
            }
        } else {
            fprintf(stderr, "Failed to write JSON report to: %s\n", options.json_file);
        }
    }

    if (options.csv_file[0] != '\0') {
        if (save_report_csv(&report, options.csv_file) == 0) {
            if (!options.quiet && options.format == FORMAT_TEXT) {
                printf("[✓] Exported structured CSV report to: %s\n", options.csv_file);
            }
        } else {
            fprintf(stderr, "Failed to write CSV report to: %s\n", options.csv_file);
        }
    }

    return exit_code;
}
