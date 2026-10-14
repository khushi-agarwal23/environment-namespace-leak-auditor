
# Member 2 – Namespace and Security Auditor

## Objective
Inspect Linux namespace identifiers and identify
potentially sensitive environment-variable names.

## Namespace Inspection
1. Get current and comparison process IDs.
2. Read namespace links from /proc/PID/ns.
3. Compare namespace identifiers.
4. Display SAME, DIFFERENT, or UNAVAILABLE.

## Security Audit
1. Read process environment variables.
2. Check variable names for sensitive keywords.
3. Display variable names with redacted values.
4. Report findings and recommendations.

## Limitations
- Namespace access depends on permissions.
- Matching namespace IDs do not prove complete isolation.
- Keyword detection can produce false positives or miss secrets.
- The module audits its own environment variables,
  not every process on the system.
- Tests were performed using GitHub Codespaces.

## Integration
Member 3 can invoke this module as a command-line program
and collect its output for reporting.
