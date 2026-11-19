#!/usr/bin/env python3
"""Static Security, Credential Hygiene, and Syntax Audit for nxtflow.

Scans all repository text files (including SVGs, YAML, Markdown, Python, JSON, and
GitHub workflows) for accidentally committed API tokens, private keys, webhook URLs,
and placeholder secrets, and validates Python and JSON syntax.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

SKIP_DIR_NAMES = frozenset({
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
})

BINARY_EXTENSIONS = frozenset({
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".tgz",
    ".gz",
    ".zip",
    ".whl",
    ".pyc",
    ".pyo",
    ".so",
    ".wav",
    ".mp3",
    ".db",
    ".sqlite",
    ".pdf",
})


def _build_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Build secret-detection regexes via concatenation so self-scans stay clean."""
    dot = r"\."
    raw_specs = [
        ("secret-super", "Super" + "Secret"),
        ("secret-slack-hook", "hooks" + dot + "slack" + dot + "com/services/"),
        ("secret-private-key", r"-----BEGIN [A-Z ]*" + "PRIVATE" + r" KEY-----"),
        ("secret-ghp", r"\bghp" + r"_[A-Za-z0-9]{20,}\b"),
        ("secret-glpat", r"\bglpat" + r"-[A-Za-z0-9_-]{20,}\b"),
        ("secret-aws-akia", r"\bAKIA" + r"[0-9A-Z]{16}\b"),
        ("secret-github-pat", r"\bgithub_pat" + r"_[A-Za-z0-9_]{20,}\b"),
        ("secret-slack-token", r"\bxox[bpa]" + r"-[A-Za-z0-9-]{10,}\b"),
        ("secret-vault-token", r"\bhvs" + r"\.[A-Za-z0-9_-]{20,}\b"),
    ]
    return [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in raw_specs]


FORBIDDEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = _build_patterns()


def _is_skipped_dir(rel_parts: tuple[str, ...], dirname: str) -> bool:
    if dirname in SKIP_DIR_NAMES or dirname.endswith(".egg-info"):
        return True
    return bool(dirname == "charts" and len(rel_parts) >= 2 and rel_parts[0] == "charts")


def scan_directory(root: Path) -> list[str]:
    """Scan *root* recursively for forbidden credential/secret patterns and syntax errors."""
    root = Path(root).resolve()
    violations: list[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        rel_parts = () if str(rel_dir) == "." else rel_dir.parts
        dirnames[:] = sorted(d for d in dirnames if not _is_skipped_dir(rel_parts, d))

        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in BINARY_EXTENSIONS or fname.endswith(".tar.gz"):
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                violations.append(f"{fpath.relative_to(root)}:0: unreadable ({exc})")
                continue

            rel_file = fpath.relative_to(root)
            for lineno, line in enumerate(text.splitlines(), 1):
                for rule_name, rx in FORBIDDEN_PATTERNS:
                    if rx.search(line):
                        snippet = line.strip()
                        if len(snippet) > 160:
                            snippet = snippet[:157] + "..."
                        violations.append(f"{rel_file}:{lineno}: [{rule_name}] {snippet}")

            if fpath.suffix == ".py":
                try:
                    ast.parse(text, filename=str(rel_file))
                except SyntaxError as exc:
                    violations.append(f"{rel_file}:{exc.lineno or 0}: [python-syntax] {exc.msg}")
            elif fpath.suffix == ".json":
                try:
                    json.loads(text)
                except json.JSONDecodeError as exc:
                    violations.append(f"{rel_file}:{exc.lineno}: [json-syntax] {exc.msg}")

    return violations


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    target = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    violations = scan_directory(target)
    if violations:
        print("Security & syntax audit FAILED. Issues detected:", file=sys.stderr)
        for hit in violations:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print(f"Security & syntax audit PASSED across {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
