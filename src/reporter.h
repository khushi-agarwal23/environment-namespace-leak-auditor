#ifndef REPORTER_H
#define REPORTER_H

#include "common.h"
#include <stdio.h>

/* Initializes report metadata (timestamp, OS, kernel) */
void init_audit_report(audit_report_t *report);

/* Prints formatted human-readable text summary to stream */
void print_report_text(const audit_report_t *report, FILE *stream, bool verbose, bool color);

/* Emits strictly valid JSON to stream */
int export_report_json(const audit_report_t *report, FILE *stream);

/* Saves JSON report to specified file path */
int save_report_json(const audit_report_t *report, const char *filepath);

/* Emits RFC-4180 compliant CSV to stream */
int export_report_csv(const audit_report_t *report, FILE *stream);

/* Saves CSV report to specified file path */
int save_report_csv(const audit_report_t *report, const char *filepath);

#endif /* REPORTER_H */
