
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

extern char **environ;

static void run_inspector(char *const args[], char *const env[]) {
    execve("./inspector", args, env);
    perror("execve");
    _exit(127);
}

int main(void) {
    if (setenv("DEMO_MODE", "test", 1) == -1 ||
        setenv("DEMO_SECRET", "dummy123", 1) == -1 ||
        setenv("API_TOKEN", "dummy-token", 1) == -1 ||
        setenv("UNRELATED_VAR", "should-not-inherit", 1) == -1) {
        perror("setenv");
        return 1;
    }

    printf("ENVIRONMENT AUDIT\n");
    printf("Parent PID: %ld\n", (long)getpid());
    fflush(stdout);

    int passed = 0;

    for (int test = 1; test <= 8; test++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            return 1;
        }

        if (pid == 0) {
            char *args1[] = {
                "./inspector", "DEMO_MODE", "P", NULL
            };
            char *args2[] = {
                "./inspector", "DEMO_SECRET", "A", NULL
            };
            char *args3[] = {
                "./inspector", "API_TOKEN", "A", NULL
            };
            char *args4[] = {
                "./inspector", "DEMO_MODE", "A", NULL
            };
            char *args5[] = {
                "./inspector", "--expect-only",
                "DEMO_MODE", "sanitized", NULL
            };
            char *args6[] = {
                "./inspector", "--expect-empty", NULL
            };
            char *args7[] = {
                "./inspector", "--absent", "DEMO_SECRET", NULL
            };
            char *args8[] = {
                "./nonexistent-inspector", NULL
            };

            char *clean_env[] = {
                "DEMO_MODE=sanitized", NULL
            };
            char *empty_env[] = {NULL};

            if (test == 2 && unsetenv("DEMO_SECRET") == -1) {
                perror("unsetenv");
                _exit(2);
            }

            if (test == 8) {
                execve(args8[0], args8, environ);

                if (errno == ENOENT) {
                    perror("execve expected failure");
                    _exit(42);
                }

                perror("execve unexpected error");
                _exit(127);
            }

            if (test == 3) {
                run_inspector(args3, clean_env);
            } else if (test == 5) {
                run_inspector(args5, clean_env);
            } else if (test == 6) {
                run_inspector(args6, empty_env);
            } else if (test == 7) {
                run_inspector(args7, clean_env);
            } else {
                char **args = test == 1 ? args1 :
                              test == 2 ? args2 : args4;

                run_inspector(args, environ);
            }
        }

        int status;

        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }

        int expected = (test == 4) ? 1 :
                       (test == 8) ? 42 : 0;

        if (WIFEXITED(status) &&
            WEXITSTATUS(status) == expected) {
            printf("TEST %d PASS\n", test);
            passed++;
        } else if (WIFEXITED(status)) {
            printf("TEST %d FAIL: expected exit %d, got %d\n",
                   test, expected, WEXITSTATUS(status));
        } else {
            printf("TEST %d FAIL: child terminated abnormally\n",
                   test);
        }
    }

    printf("\nAudit summary: %d/8 tests passed\n", passed);
    return passed == 8 ? 0 : 1;
}
