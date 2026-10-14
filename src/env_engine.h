#ifndef ENV_ENGINE_H
#define ENV_ENGINE_H

#include "common.h"

/*
 * Runs the Member 1 environment propagation audit suite.
 * Executes 8 controlled process creation tests using fork(), execve(), and waitpid().
 * Populates results structure.
 * Returns 0 if all tests pass, or the number of failed tests.
 */
int run_environment_audit(env_audit_results_t *results, bool verbose, bool quiet);

#endif /* ENV_ENGINE_H */
