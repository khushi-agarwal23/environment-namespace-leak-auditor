
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

extern char **environ;

static int is_sensitive_name(const char *name) {
    char upper[256];
    size_t i;

    for (i = 0; name[i] != '\0' && i < sizeof(upper) - 1; i++) {
        upper[i] = (char)toupper((unsigned char)name[i]);
    }
    upper[i] = '\0';

    return strstr(upper, "SECRET") != NULL ||
           strstr(upper, "PASSWORD") != NULL ||
           strstr(upper, "TOKEN") != NULL ||
           strstr(upper, "API_KEY") != NULL ||
           strstr(upper, "PRIVATE_KEY") != NULL ||
           strstr(upper, "CREDENTIAL") != NULL;
}

static int scan_sensitive_variables(void) {
    int found = 0;

    printf("SENSITIVE VARIABLE SCAN\n");

    for (char **entry = environ; *entry != NULL; entry++) {
        const char *equals = strchr(*entry, '=');

        if (equals == NULL) {
            continue;
        }

        size_t length = (size_t)(equals - *entry);

        if (length == 0 || length >= 256) {
            continue;
        }

        char name[256];
        memcpy(name, *entry, length);
        name[length] = '\0';

        if (is_sensitive_name(name)) {
            printf("WARNING: Potentially sensitive variable: %s "
                   "[value redacted]\n", name);
            found++;
        }
    }

    if (found == 0) {
        printf("No potentially sensitive variable names detected.\n");
    }

    printf("Scan summary: %d potentially sensitive variable(s)\n", found);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--scan-sensitive") == 0) {
        return scan_sensitive_variables();
    }

    if (argc == 4 && strcmp(argv[1], "--equals") == 0) {
        const char *actual = getenv(argv[2]);

        printf("Inspector PID: %ld\n", (long)getpid());

        if (actual != NULL && strcmp(actual, argv[3]) == 0) {
            printf("PASS: %s matches expected value\n", argv[2]);
            return 0;
        }

        printf("FAIL: %s does not match expected value\n", argv[2]);
        return 1;
    }

    if (argc == 3 && strcmp(argv[1], "--absent") == 0) {
        const char *actual = getenv(argv[2]);

        printf("Inspector PID: %ld\n", (long)getpid());

        if (actual == NULL) {
            printf("PASS: %s is absent\n", argv[2]);
            return 0;
        }

        printf("FAIL: %s is present but should be absent\n", argv[2]);
        return 1;
    }

    if (argc != 3) {
        fprintf(stderr,
                "Usage: inspector VARIABLE P|A\n"
                "       inspector --equals VARIABLE VALUE\n"
                "       inspector --absent VARIABLE\n"
                "       inspector --scan-sensitive\n");
        return 2;
    }

    const char *name = argv[1];
    const char *expected = argv[2];
    const char *actual = getenv(name);

    printf("Inspector PID: %ld\n", (long)getpid());

    if (strcmp(expected, "P") == 0) {
        if (actual != NULL) {
            printf("PASS: %s is present\n", name);
            return 0;
        }
    } else if (strcmp(expected, "A") == 0) {
        if (actual == NULL) {
            printf("PASS: %s is absent\n", name);
            return 0;
        }
    } else {
        fprintf(stderr, "Expected value must be P or A\n");
        return 2;
    }

    printf("FAIL: %s did not match expectation\n", name);
    return 1;
}
