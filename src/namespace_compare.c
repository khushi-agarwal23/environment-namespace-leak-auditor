
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

static const char *namespaces[] = {
    "cgroup", "ipc", "mnt", "net", "pid",
    "time", "user", "uts"
};

static int get_namespace_id(long pid, const char *name,
                            char *result, size_t result_size) {
    char path[128];
    char link[256];

    int length = snprintf(path, sizeof(path),
                          "/proc/%ld/ns/%s", pid, name);

    if (length < 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }

    ssize_t size = readlink(path, link, sizeof(link) - 1);

    if (size < 0) {
        return -1;
    }

    link[size] = '\0';

    if ((size_t)size >= result_size) {
        return -1;
    }

    memcpy(result, link, (size_t)size + 1);
    return 0;
}

static int valid_pid(const char *text, long *pid) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0' ||
        value <= 0 || value > INT_MAX) {
        return 0;
    }

    *pid = value;
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s PID1 PID2\n", argv[0]);
        return 2;
    }

    long pid1, pid2;

    if (!valid_pid(argv[1], &pid1) ||
        !valid_pid(argv[2], &pid2)) {
        fprintf(stderr, "Error: both PIDs must be positive integers\n");
        return 2;
    }

    struct stat info;

    if (stat("/proc", &info) == -1) {
        perror("Cannot access /proc");
        return 1;
    }

    printf("NAMESPACE COMPARISON\n");
    printf("Process 1 PID: %ld\n", pid1);
    printf("Process 2 PID: %ld\n\n", pid2);

    int compared = 0;
    int errors = 0;

    for (size_t i = 0;
         i < sizeof(namespaces) / sizeof(namespaces[0]);
         i++) {
        char ns1[256], ns2[256];

        int result1 = get_namespace_id(
            pid1, namespaces[i], ns1, sizeof(ns1));
        int result2 = get_namespace_id(
            pid2, namespaces[i], ns2, sizeof(ns2));

        if (result1 != 0 || result2 != 0) {
            printf("%-8s Unable to compare\n", namespaces[i]);
            errors++;
            continue;
        }

        if (strcmp(ns1, ns2) == 0) {
            printf("%-8s SAME       %s\n", namespaces[i], ns1);
        } else {
            printf("%-8s DIFFERENT  %s | %s\n",
                   namespaces[i], ns1, ns2);
        }

        compared++;
    }

    printf("\nNamespaces compared: %d\n", compared);

    if (errors > 0) {
        printf("Comparison errors: %d\n", errors);
        return 1;
    }

    return 0;
}
