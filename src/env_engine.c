#define _POSIX_C_SOURCE 200809L
#include "env_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

extern char **environ;

static const char *get_inspector_binary(void) {
    const char *env_path = getenv("INSPECTOR_PATH");
    if (env_path != NULL && access(env_path, X_OK) == 0) {
        return env_path;
    }
    if (access("./inspector", X_OK) == 0) {
        return "./inspector";
    }
    if (access("bin/inspector", X_OK) == 0) {
        return "bin/inspector";
    }
    return "./inspector";
}

static void run_inspector_exec(const char *inspector_path, char *const args[], char *const env[]) {
    execve(inspector_path, args, env);
    perror("execve");
    _exit(127);
}

int run_environment_audit(env_audit_results_t *results, bool verbose, bool quiet) {
    if (!results) return -1;

    memset(results, 0, sizeof(*results));
    results->parent_pid = getpid();
    results->total_tests = 8;

    /* Setup test environment */
    if (setenv("DEMO_MODE", "test", 1) == -1 ||
        setenv("DEMO_SECRET", "dummy123", 1) == -1 ||
        setenv("API_TOKEN", "dummy-token", 1) == -1 ||
        setenv("UNRELATED_VAR", "should-not-inherit", 1) == -1) {
        perror("setenv");
        return -1;
    }

    const char *inspector_bin = get_inspector_binary();

    struct {
        int id;
        const char *name;
        const char *description;
        const char *target_var;
        const char *expectation;
        int expected_exit;
    } test_defs[8] = {
        {1, "Inherited Variable Propagation", "Check DEMO_MODE inherits from parent environment", "DEMO_MODE", "Present (P)", 0},
        {2, "Child Unsetenv Removal", "Verify DEMO_SECRET is absent after unsetenv() in child", "DEMO_SECRET", "Absent (A)", 0},
        {3, "Explicit Clean Environment", "Pass custom environment excluding API_TOKEN", "API_TOKEN", "Absent (A)", 0},
        {4, "Negative Expectation Assertion", "Assert child detects unexpected variable presence", "DEMO_MODE", "Absent (fails expectation)", 1},
        {5, "Exact Single Variable Isolation", "Verify clean env contains only DEMO_MODE=sanitized", "DEMO_MODE", "Matches 'sanitized'", 0},
        {6, "Empty Environment Execution", "Verify execve with empty env array leaves child environ empty", "(ALL)", "Empty environment", 0},
        {7, "Explicit Secret Exclusion", "Verify DEMO_SECRET is stripped when running with clean env", "DEMO_SECRET", "Absent (A)", 0},
        {8, "Execve Failure Handling", "Verify process handles ENOENT for non-existent executable", "N/A", "Exit code 42 on ENOENT", 42}
    };

    if (!quiet) {
        printf("\n======================================================\n");
        printf("       PROCESS & ENVIRONMENT PROPAGATION ENGINE       \n");
        printf("======================================================\n");
        printf("Parent PID: %ld\n", (long)results->parent_pid);
        printf("Inspector Path: %s\n\n", inspector_bin);
    }

    for (int t = 0; t < 8; t++) {
        int test_idx = t + 1;
        env_test_record_t *rec = &results->tests[t];
        rec->test_id = test_defs[t].id;
        snprintf(rec->name, sizeof(rec->name), "%s", test_defs[t].name);
        snprintf(rec->description, sizeof(rec->description), "%s", test_defs[t].description);
        snprintf(rec->target_var, sizeof(rec->target_var), "%s", test_defs[t].target_var);
        snprintf(rec->expectation, sizeof(rec->expectation), "%s", test_defs[t].expectation);
        rec->expected_exit = test_defs[t].expected_exit;

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            snprintf(rec->details, sizeof(rec->details), "fork failed: %s", strerror(errno));
            rec->passed = false;
            results->failed_tests++;
            continue;
        }

        if (pid == 0) {
            /* Child process execution */
            if (quiet) {
                FILE *null_out = freopen("/dev/null", "w", stdout);
                (void)null_out;
                FILE *null_err = freopen("/dev/null", "w", stderr);
                (void)null_err;
            }

            char *args1[] = {(char *)inspector_bin, "DEMO_MODE", "P", NULL};
            char *args2[] = {(char *)inspector_bin, "DEMO_SECRET", "A", NULL};
            char *args3[] = {(char *)inspector_bin, "API_TOKEN", "A", NULL};
            char *args4[] = {(char *)inspector_bin, "DEMO_MODE", "A", NULL};
            char *args5[] = {(char *)inspector_bin, "--expect-only", "DEMO_MODE", "sanitized", NULL};
            char *args6[] = {(char *)inspector_bin, "--expect-empty", NULL};
            char *args7[] = {(char *)inspector_bin, "--absent", "DEMO_SECRET", NULL};
            char *args8[] = {"./nonexistent-inspector", NULL};

            char *clean_env[] = {"DEMO_MODE=sanitized", NULL};
            char *empty_env[] = {NULL};

            if (test_idx == 2 && unsetenv("DEMO_SECRET") == -1) {
                perror("unsetenv");
                _exit(2);
            }

            if (test_idx == 8) {
                execve(args8[0], args8, environ);
                if (errno == ENOENT) {
                    _exit(42);
                }
                _exit(127);
            }

            if (test_idx == 3) {
                run_inspector_exec(inspector_bin, args3, clean_env);
            } else if (test_idx == 5) {
                run_inspector_exec(inspector_bin, args5, clean_env);
            } else if (test_idx == 6) {
                run_inspector_exec(inspector_bin, args6, empty_env);
            } else if (test_idx == 7) {
                run_inspector_exec(inspector_bin, args7, clean_env);
            } else {
                char **args = (test_idx == 1) ? args1 :
                              (test_idx == 2) ? args2 : args4;
                run_inspector_exec(inspector_bin, args, environ);
            }
        }

        int status = 0;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            snprintf(rec->details, sizeof(rec->details), "waitpid error: %s", strerror(errno));
            rec->passed = false;
            results->failed_tests++;
            continue;
        }

        if (WIFEXITED(status)) {
            rec->actual_exit = WEXITSTATUS(status);
            if (rec->actual_exit == rec->expected_exit) {
                rec->passed = true;
                results->passed_tests++;
                snprintf(rec->details, sizeof(rec->details),
                         "Child %ld exited with expected code %d", (long)pid, rec->actual_exit);
            } else {
                rec->passed = false;
                results->failed_tests++;
                snprintf(rec->details, sizeof(rec->details),
                         "Expected exit %d, got %d", rec->expected_exit, rec->actual_exit);
            }
        } else if (WIFSIGNALED(status)) {
            rec->actual_exit = -WTERMSIG(status);
            rec->passed = false;
            results->failed_tests++;
            snprintf(rec->details, sizeof(rec->details),
                     "Child terminated abnormally by signal %d", WTERMSIG(status));
        }

        if (!quiet) {
            if (rec->passed) {
                printf("[TEST %d] PASS: %-32s (Exit: %d)\n",
                       rec->test_id, rec->name, rec->actual_exit);
            } else {
                printf("[TEST %d] FAIL: %-32s (%s)\n",
                       rec->test_id, rec->name, rec->details);
            }
            if (verbose) {
                printf("          Target Var: %s | Expectation: %s\n",
                       rec->target_var, rec->expectation);
            }
        }
    }

    if (!quiet) {
        printf("\nEnvironment Engine Summary: %d/%d tests passed (Passed: %d, Failed: %d)\n",
               results->passed_tests, results->total_tests,
               results->passed_tests, results->failed_tests);
    }

    return results->failed_tests;
}
