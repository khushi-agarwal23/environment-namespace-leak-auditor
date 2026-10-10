
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

extern char **environ;

int main(void) {
    if (setenv("DEMO_MODE", "test", 1) == -1 ||
        setenv("DEMO_SECRET", "dummy123", 1) == -1 ||
        setenv("API_TOKEN", "dummy-token", 1) == -1) {
        perror("setenv");
        return 1;
    }

    printf("ENVIRONMENT AUDIT\n");
    printf("Parent PID: %ld\n", (long)getpid());
    fflush(stdout);

    int passed = 0;

    for (int test = 1; test <= 4; test++) {
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

            char *clean_env[] = {
                "DEMO_MODE=sanitized", NULL
            };

            if (test == 2 && unsetenv("DEMO_SECRET") == -1) {
                perror("unsetenv");
                _exit(2);
            }

            char **args = test == 1 ? args1 :
                          test == 2 ? args2 :
                          test == 3 ? args3 : args4;

            char **env = test == 3 ? clean_env : environ;

            execve("./inspector", args, env);

            perror("execve");
            _exit(127);
        }

        int status;

        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }

        if (!WIFEXITED(status)) {
            printf("TEST %d FAIL: child terminated abnormally\n", test);
            continue;
        }

        int exit_code = WEXITSTATUS(status);

        if (test == 4) {
            if (exit_code == 1) {
                printf("TEST 4 PASS: inspector detected expected mismatch\n");
                passed++;
            } else {
                printf("TEST 4 FAIL: expected exit status 1, got %d\n",
                       exit_code);
            }
        } else if (exit_code == 0) {
            passed++;
        } else {
            printf("TEST %d FAIL: inspector exited with status %d\n",
                   test, exit_code);
        }
    }

    printf("\nAudit summary: %d/4 tests passed\n", passed);

    return passed == 4 ? 0 : 1;
}
