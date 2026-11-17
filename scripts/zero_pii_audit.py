#!/usr/bin/env python3
"""Zero-PII and Secret Sanitization Audit for nxtflow.

Scans all repository text files (including SVGs, YAML, Markdown, Python, JSON, and
GitHub workflows) for internal infrastructure IPs, private hostnames, personal
identifiers, and credential patterns while allowing RFC 5737 / RFC 1918 / RFC 3849 /
RFC 2606 documentation examples.
"""

from __future__ import annotations

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
    """Build forbidden regexes via concatenation so self-scans stay clean with zero blind spots."""
    dot = r"\."
    raw_specs = [
        ("internal-subnet-172-28", "172" + dot + "28" + dot),
        ("internal-subnet-192-168-231", "192" + dot + "168" + dot + "231" + dot),
        ("internal-subnet-10-233", r"\b10" + dot + "233" + dot),
        ("internal-subnet-10-249", r"\b10" + dot + "249" + dot),
        ("internal-wan-47-154", r"\b47" + dot + "154" + dot + "50" + dot),
        ("internal-ip-208-113", r"\b208" + dot + "113" + dot),
        ("internal-domain-home", "home" + dot + "nert" + "work"),
        ("internal-domain-kube", "kube" + dot + "(?:home|cloud)" + dot + "nert" + "work"),
        ("internal-domain-git", "git" + dot + "nert" + "work" + dot + "com"),
        ("internal-domain-vault", "vault" + dot + "nert" + "work" + dot + "com"),
        ("internal-domain-grafana", "grafana" + dot + "nert" + "work" + dot + "com"),
        ("internal-domain-bb", "blue" + "bubbles" + dot + "(?:ilb|home)"),
        ("internal-host-slb", "slb" + "-" + "srv"),
        ("internal-host-proxmox", "prox" + "mox-(?:sm1|nuc)"),
        ("internal-org-id", "fi" + "serv"),
        ("personal-id-1", "Amber" + "wood"),
        ("personal-id-2", "Spon" + "see"),
        ("personal-user", r"\bj" + r"farr\b"),
        ("internal-wan-label", "wan" + "-" + "frontier"),
        ("secret-super", "Super" + "Secret"),
        ("secret-slack-hook", "hooks" + dot + "slack" + dot + "com"),
        ("secret-private-key", r"-----BEGIN [A-Z ]*" + "PRIVATE" + r" KEY-----"),
        ("secret-ghp", r"\bghp" + r"_[A-Za-z0-9]{20,}\b"),
        ("secret-glpat", r"\bglpat" + r"-[A-Za-z0-9_-]{20,}\b"),
        ("secret-aws-akia", r"\bAKIA" + r"[0-9A-Z]{16}\b"),
    ]
    return [(name, re.compile(pattern, re.IGNORECASE)) for name, pattern in raw_specs]


FORBIDDEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = _build_patterns()


def _is_skipped_dir(rel_parts: tuple[str, ...], dirname: str) -> bool:
    if dirname in SKIP_DIR_NAMES or dirname.endswith(".egg-info"):
        return True
    return bool(dirname == "charts" and len(rel_parts) >= 2 and rel_parts[0] == "charts")


def scan_directory(root: Path) -> list[str]:
    """Scan *root* recursively and return formatted violation lines."""
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

    return violations


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    target = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    violations = scan_directory(target)
    if violations:
        print("Zero-PII audit FAILED. Forbidden patterns detected:", file=sys.stderr)
        for hit in violations:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print(f"Zero-PII audit PASSED across {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
