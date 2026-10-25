"""Inspectors for detecting SQL injection, path traversal, and malicious command patterns."""

from __future__ import annotations

import re

# Dangerous SQL operations that alter or destroy schema/data
DESTRUCTIVE_SQL_PATTERN = re.compile(
    r"\b(DROP\s+TABLE|DROP\s+VIEW|DROP\s+DATABASE|DELETE\s+FROM|TRUNCATE|ALTER\s+TABLE|ATTACH\s+DATABASE|DETACH\s+DATABASE|PRAGMA|VACUUM)\b",
    re.IGNORECASE,
)

# Mutating SQL operations that add or update records
MUTATING_SQL_PATTERN = re.compile(
    r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|CREATE\s+TABLE|REPLACE\s+INTO)\b",
    re.IGNORECASE,
)

# Path traversal patterns targeting parent directories or absolute root
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/\.\.|\\\.\.|^/|^\\|/etc/|/root/|/proc/|/sys/|/var/run/|c:\\|windows\\)",
    re.IGNORECASE,
)

# Prompt injection keywords attempting to override guardrail policies
PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(all\s+)?previous\s+(instructions|rules|safety|protocols)|system\s+override|bypass\s+guardrails|jailbreak|disregard\s+security)",
    re.IGNORECASE,
)


def inspect_sql_query(query: str, blocked_keywords: list[str] | None = None) -> tuple[str, list[str]]:
    """Analyze SQL query for safety classification and destructive commands.

    Returns: ('read' | 'mutation' | 'forbidden', list_of_violations)
    """
    clean_sql = query.strip()
    violations: list[str] = []

    # Check for destructive/forbidden operations
    destructive_match = DESTRUCTIVE_SQL_PATTERN.search(clean_sql)
    if destructive_match:
        violations.append(f"Forbidden destructive SQL command: '{destructive_match.group(0).upper()}'")

    # Check custom blocked keywords
    if blocked_keywords:
        for kw in blocked_keywords:
            if re.search(rf"\b{re.escape(kw)}\b", clean_sql, re.IGNORECASE):
                violations.append(f"Blocked SQL keyword: '{kw.upper()}'")

    if violations:
        return "forbidden", violations

    # Check for mutation operations
    mutating_match = MUTATING_SQL_PATTERN.search(clean_sql)
    if mutating_match:
        return "mutation", []

    # Safe read (SELECT, EXPLAIN, etc.)
    return "read", []


def inspect_file_path(path: str) -> tuple[bool, list[str]]:
    """Check if file path contains directory traversal or root targeting patterns.

    Returns: (is_safe, list_of_violations)
    """
    clean_path = path.strip()
    violations: list[str] = []

    if not clean_path:
        violations.append("Empty file path")
        return False, violations

    if PATH_TRAVERSAL_PATTERN.search(clean_path):
        violations.append(f"Path traversal sequence detected in '{clean_path}'")
        return False, violations

    return True, []


def inspect_prompt_injection(text: str) -> tuple[bool, list[str]]:
    """Detect common prompt injection strings attempting safety overrides.

    Returns: (is_clean, list_of_violations)
    """
    violations: list[str] = []
    match = PROMPT_INJECTION_PATTERN.search(text)
    if match:
        violations.append(f"Prompt injection pattern detected: '{match.group(0)}'")
        return False, violations

    return True, []
