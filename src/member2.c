
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

extern char **environ;

// Check for sensitive variable names
int sensitive(const char *name, size_t n) {
    char s[256];
    if (n >= sizeof(s)) return 0;

    for (size_t i = 0; i < n; i++)
        s[i] = toupper((unsigned char)name[i]);

    s[n] = '\0';

    return strstr(s, "PASSWORD") ||
           strstr(s, "TOKEN") ||
           strstr(s, "SECRET") ||
           strstr(s, "API_KEY") ||
           strstr(s, "PRIVATE_KEY");
}

// Compare namespaces of two processes
void check_namespaces(pid_t pid) {
    const char *types[] = {
        "pid", "mnt", "net", "ipc",
        "uts", "user", "cgroup", "time"
    };

    char path1[128], path2[128];
    char a[256], b[256];

    printf("\n===== NAMESPACE AUDIT =====\n");
    printf("Current PID: %ld\n", (long)getpid());
    printf("Compared PID: %ld\n\n", (long)pid);

    for (int i = 0; i < 8; i++) {
        snprintf(path1, sizeof(path1),
                 "/proc/self/ns/%s", types[i]);

        snprintf(path2, sizeof(path2),
                 "/proc/%ld/ns/%s",
                 (long)pid, types[i]);

        ssize_t x = readlink(path1, a, sizeof(a)-1);
        int err1 = errno;
        ssize_t y = readlink(path2, b, sizeof(b)-1);
        int err2 = errno;

        if (x < 0 || y < 0) {
            printf("%s: UNAVAILABLE (%s)\n",
                   types[i],
                   strerror(x < 0 ? err1 : err2));
            continue;
        }

        a[x] = '\0';
        b[y] = '\0';

        printf("%s: %s | %s\n", types[i], a, b);
        printf("Result: %s\n\n",
               strcmp(a, b) == 0 ?
               "SAME" : "DIFFERENT");
    }
}

// Detect and redact sensitive environment variables
void security_audit() {
    int count = 0;

    printf("\n===== SECURITY AUDIT =====\n");

    for (char **p = environ; *p; p++) {
        char *eq = strchr(*p, '=');
        if (!eq) continue;

        size_t n = eq - *p;

        if (sensitive(*p, n)) {
            printf("Variable: %.*s\n", (int)n, *p);
            printf("Value: [REDACTED]\n");
            printf("Level: REVIEW REQUIRED\n");
            printf("Recommendation: Limit secret exposure.\n\n");
            count++;
        }
    }

    printf("Total findings: %d\n", count);

    if (count == 0)
        printf("No sensitive-looking variables detected.\n");
}

int main(int argc, char *argv[]) {
    pid_t pid = getppid();

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [PID]\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        char *end;
        errno = 0;
        long value = strtol(argv[1], &end, 10);

        if (errno || *end || value <= 0 || value > INT_MAX) {
            fprintf(stderr, "Invalid PID\n");
            return 1;
        }

        pid = (pid_t)value;
    }

    check_namespaces(pid);
    security_audit();

    return 0;
}
