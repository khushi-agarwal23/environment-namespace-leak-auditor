#ifndef NS_SEC_ENGINE_H
#define NS_SEC_ENGINE_H

#include "common.h"

/*
 * Checks whether an environment variable name matches sensitive keywords
 * (PASSWORD, TOKEN, SECRET, API_KEY, PRIVATE_KEY, CREDENTIAL).
 * If matched_kw is non-NULL, copies the matched keyword name.
 * Returns 1 if sensitive, 0 otherwise.
 */
int is_sensitive_variable_name(const char *name, size_t len, char *matched_kw, size_t kw_buf_size);

/*
 * Inspects Linux namespaces between current process and target PID.
 * Inspects: pid, mnt, net, ipc, uts, user, cgroup, time
 * Populates ns_audit_results_t.
 * Returns 0 on success (even if some or all namespaces are unavailable on the platform).
 */
int run_namespace_audit(pid_t target_pid, ns_audit_results_t *results, bool verbose, bool quiet);

/*
 * Performs security audit on process environment.
 * Detects sensitive-looking variables and creates redacted records.
 * Populates sec_audit_results_t.
 * Returns the number of findings.
 */
int run_security_audit(sec_audit_results_t *results, bool verbose, bool quiet);

#endif /* NS_SEC_ENGINE_H */
