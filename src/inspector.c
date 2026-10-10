
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: inspector VARIABLE EXPECTED\n");
        return 2;
    }

    const char *name = argv[1];
    const char *expected = argv[2];
    const char *actual = getenv(name);

    printf("Inspector PID: %ld\n", (long)getpid());

    if (expected[0] == 'P') {
        if (actual != NULL) {
            printf("PASS: %s is present\n", name);
            return 0;
        }
    } else if (expected[0] == 'A') {
        if (actual == NULL) {
            printf("PASS: %s is absent\n", name);
            return 0;
        }
    }

    printf("FAIL: %s did not match expectation\n", name);
    return 1;
}
