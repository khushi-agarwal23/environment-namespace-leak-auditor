#!/bin/bash

set -u

gcc -Wall -Wextra src/member2.c -o member2 || exit 1

echo "TEST 1: Namespace inspection"
./member2

echo "TEST 2: Sensitive variables"
env -i PATH="$PATH" API_TOKEN=demo123 PASSWORD=test123 ./member2

echo "TEST 3: Normal variables"
env -i PATH="$PATH" NAME=Student COURSE=OS ./member2

echo "TEST 4: Invalid PID"
./member2 abc

echo "TEST 5: Nonexistent PID"
./member2 99999999

echo "All test scenarios executed."
