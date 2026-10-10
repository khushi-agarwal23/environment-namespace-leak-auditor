
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

static const char *namespaces[] = {
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_for_children",
    "user",
    "uts"
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s PID\n", argv[0]);
        return 2;
    }

    char *end = NULL;
    errno = 0;
    long pid = strtol(argv[1], &end, 10);

    if (errno != 0 || end == argv[1] || *end != '\0' ||
        pid <= 0 || pid > INT_MAX) {
        fprintf(stderr, "Error: PID must be a positive integer\n");
        return 2;
    }

    printf("LINUX NAMESPACE AUDIT\n");
    printf("Target PID: %ld\n\n", pid);

    int found = 0;
    int errors = 0;

    for (size_t i = 0;
         i < sizeof(namespaces) / sizeof(namespaces[0]);
         i++) {
        char path[128];
        char target[256];

        int length = snprintf(path, sizeof(path),
                              "/proc/%ld/ns/%s",
                              pid, namespaces[i]);

        if (length < 0 || (size_t)length >= sizeof(path)) {
            fprintf(stderr, "Error: namespace path too long\n");
            return 1;
        }

        ssize_t size = readlink(path, target, sizeof(target) - 1);

        if (size == -1) {
            if (errno == ENOENT) {
                printf("%-18s Not available\n", namespaces[i]);
            } else {
                printf("%-18s Unable to inspect (%s)\n",
                       namespaces[i], strerror(errno));
                errors++;
            }
            continue;
        }

        target[size] = '\0';
        printf("%-18s %s\n", namespaces[i], target);
        found++;
    }

    printf("\nNamespaces inspected: %d\n", found);

    if (found == 0) {
        fprintf(stderr,
                "Error: no namespace links could be inspected for PID %ld\n",
                pid);
        return 1;
    }

    if (errors > 0) {
        printf("Inspection errors: %d\n", errors);
        return 1;
    }

    return 0;
}
