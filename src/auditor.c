
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

    int failures = 0;

    for (int test = 1; test <= 3; test++) {
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

            char *clean_env[] = {
                "DEMO_MODE=sanitized", NULL
            };

            if (test == 2 && unsetenv("DEMO_SECRET") == -1) {
                perror("unsetenv");
                _exit(2);
            }

            char **args = test == 1 ? args1 :
                          test == 2 ? args2 : args3;

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

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            failures++;
        }
    }

    printf("\nAudit summary: %d/3 tests passed\n", 3 - failures);

    return failures == 0 ? 0 : 1;
}
