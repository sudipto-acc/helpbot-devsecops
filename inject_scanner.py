#!/usr/bin/env python3
"""Gate 4 - custom prompt-injection scanner.

Searches every .py file in the repository for hardcoded system prompt definitions
(SYSTEM_PROMPT / system_message assignments and "system" role messages) and for common
prompt-injection bypass phrases. Exits 1 if any match is found, 0 if the code is clean.

The patterns are written as regular expressions (whitespace as \\s+ / \\s*) so this file never
contains a literal trigger string and is scanned like every other .py file.

Usage: python inject_scanner.py [repo_root]
"""
import os
import re
import sys
from pathlib import Path

# Hardcoded system prompt definitions (prompt variable assignments and system-role chat messages)
SYSTEM_PROMPT_PATTERNS = [
    r"SYSTEM_PROMPT\s*=(?!=)",
    r"system_message\s*=(?!=)",
    r"""["']role["']\s*:\s*["']system["']""",
]

# Common prompt-injection bypass phrases
INJECTION_PHRASES = [
    r"ignore\s+previous\s+instructions",
    r"you\s+are\s+now",
    r"pretend\s+you\s+are",
    r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
]

COMPILED = (
    [("hardcoded-system-prompt", re.compile(p, re.IGNORECASE)) for p in SYSTEM_PROMPT_PATTERNS]
    + [("injection-phrase", re.compile(p, re.IGNORECASE)) for p in INJECTION_PHRASES]
)

# Virtual environments and build output are not repository source code
SKIP_DIRS = {".git", ".venv", "venv", "env", "site-packages", "node_modules", "__pycache__", "build", "dist"}


def iter_python_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield Path(dirpath, name)


def scan_file(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.split("\n")
    findings = []
    for rule_id, regex in COMPILED:
        for match in regex.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            findings.append((line_no, rule_id, " ".join(match.group(0).split()), lines[line_no - 1].strip()))
    return sorted(findings)


def gh_escape(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    files = list(iter_python_files(root))
    print(f"[Gate 4] Prompt-injection scanner: checking {len(files)} .py file(s) under {root}")

    total = 0
    for path in files:
        rel = path.relative_to(root).as_posix()
        findings = scan_file(path)
        print(f"  {'FAIL' if findings else 'ok  '} {rel}")
        for line_no, rule_id, matched, line in findings:
            total += 1
            message = f"{rule_id}: matched '{matched}' -> {line[:120]}"
            print(f"       {rel}:{line_no}  {message}")
            if in_actions:
                print(f"::error file={rel},line={line_no},title=Gate 4 inject_scanner ({rule_id})::{gh_escape(message)}")

    if total:
        print(f"[Gate 4] FAILED: {total} match(es). Move system prompts out of source code "
              "(environment variable / secret store) and remove prompt-injection phrases.")
        return 1
    print("[Gate 4] PASSED: no hardcoded system prompts or injection phrases found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
