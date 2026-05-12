#!/usr/bin/env python3
"""
Mini Shai-Hulud npm worm detector (read-only audit).

WARNING: This script intentionally performs NO destructive actions and does
NOT revoke any tokens. The worm reportedly contains a dead-man's-switch that
triggers `rm -rf ~/` if its tokens are revoked while the daemon is alive.
Run this audit first, then plan remediation from an isolated environment.

Usage:
    python3 check_shai_hulud.py                      # scan $HOME
    python3 check_shai_hulud.py /path/to/scan ...    # scan specific roots
    python3 check_shai_hulud.py --no-github          # skip gh CLI checks
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# --- Indicators of compromise -------------------------------------------------

SUSPICIOUS_FILENAMES = {
    "router_init.js",
    "setup.mjs",
    "format-check.yml",
}

SUSPICIOUS_WORKFLOW_RELPATH = Path(".github") / "workflows" / "format-check.yml"

SUSPICIOUS_CONFIG_FILES = {
    Path(".vscode") / "tasks.json",
    Path(".claude") / "settings.json",
}

# Strings that, if found inside the config files above, are highly suspicious.
SUSPICIOUS_CONFIG_PATTERNS = [
    re.compile(r"\.claude/setup\.mjs", re.IGNORECASE),
    re.compile(r"SessionStart", re.IGNORECASE),
    re.compile(r"router_init\.js", re.IGNORECASE),
    re.compile(r"gh-token-monitor", re.IGNORECASE),
]

SUSPICIOUS_PROCESS_NAMES = {"gh-token-monitor"}

SUSPICIOUS_REPO_NAMES = {"shai-hulud", "shai-hulud migration"}

SUSPICIOUS_BRANCH_PREFIX = "dependabout/"

SUSPICIOUS_ARTIFACT_NAMES = {"format-results"}

# Directories to skip when walking (noisy, unlikely to contain IoCs at depth).
WALK_SKIP_DIRS = {
    ".git",
    "node_modules",  # we still inspect lockfiles at the project root level
    "Library",       # macOS user Library — huge and out of scope
    ".Trash",
    ".cache",
    ".npm",
    "Pictures",
    "Movies",
    "Music",
}

# How far down we walk before stopping (relative to each scan root).
MAX_DEPTH = 8


# --- Finding model ------------------------------------------------------------

SEVERITY_HIGH = "HIGH"
SEVERITY_MED = "MED"
SEVERITY_INFO = "INFO"


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    location: str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    scanned_roots: list[str] = field(default_factory=list)
    files_scanned: int = 0

    def add(self, severity: str, category: str, message: str, location: str = "") -> None:
        self.findings.append(Finding(severity, category, message, location))


# --- Filesystem scan ----------------------------------------------------------

def walk_limited(
    root: Path,
    max_depth: int,
    on_error: "callable[[OSError], None] | None" = None,
) -> Iterable[tuple[Path, list[str], list[str]]]:
    try:
        root = root.resolve()
    except OSError:
        # Some paths can't be resolved (broken symlinks, FUSE mounts).
        # Walk them as-given.
        pass
    root_parts = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        depth = len(Path(dirpath).parts) - root_parts
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in WALK_SKIP_DIRS]
        yield Path(dirpath), dirnames, filenames


_TTY = sys.stderr.isatty()


def _term_width(default: int = 100) -> int:
    try:
        return max(20, shutil.get_terminal_size((default, 20)).columns)
    except OSError:
        return default


def progress(msg: str) -> None:
    """Permanent line (newline-terminated)."""
    if _TTY:
        # Clear any in-place line first.
        sys.stderr.write("\r" + " " * _term_width() + "\r")
    print(msg, file=sys.stderr, flush=True)


def progress_inplace(msg: str) -> None:
    """Overwrite the current line. Falls back to nothing on non-TTY."""
    if not _TTY:
        return
    width = _term_width()
    line = msg if len(msg) <= width - 1 else "..." + msg[-(width - 4):]
    sys.stderr.write("\r" + line.ljust(width - 1))
    sys.stderr.flush()


def progress_clear() -> None:
    if _TTY:
        sys.stderr.write("\r" + " " * _term_width() + "\r")
        sys.stderr.flush()


def scan_filesystem(root: Path, report: Report) -> None:
    if not root.exists():
        report.add(SEVERITY_INFO, "scan", f"Path does not exist: {root}", str(root))
        return

    progress(f"[scan] walking {root} ...")

    perm_denied: list[str] = []
    other_errors: list[str] = []

    def _on_walk_error(err: OSError) -> None:
        target = getattr(err, "filename", None) or str(err)
        if isinstance(err, PermissionError):
            perm_denied.append(str(target))
        else:
            other_errors.append(f"{target}: {err}")

    for dirpath, dirnames, filenames in walk_limited(root, MAX_DEPTH, on_error=_on_walk_error):
        report.files_scanned += len(filenames)
        progress_inplace(f"[scan] {dirpath}")

        # Filename-based IoCs.
        for fname in filenames:
            if fname in SUSPICIOUS_FILENAMES:
                full = dirpath / fname
                # format-check.yml inside .github/workflows is the strongest signal.
                rel_workflow = (
                    fname == "format-check.yml"
                    and dirpath.name == "workflows"
                    and dirpath.parent.name == ".github"
                )
                sev = SEVERITY_HIGH if rel_workflow or fname in {"router_init.js", "setup.mjs"} else SEVERITY_MED
                report.add(
                    sev,
                    "suspicious-file",
                    f"Found suspicious file '{fname}'"
                    + (" in .github/workflows/" if rel_workflow else ""),
                    str(full),
                )

        # Inspect known config files for embedded IoCs.
        for rel in SUSPICIOUS_CONFIG_FILES:
            if rel.parts[0] not in dirnames:
                continue
            candidate = dirpath / rel
            try:
                is_file = candidate.is_file()
            except OSError as e:
                # Synthetic filesystems (FUSE mounts, snapshots) can raise
                # EINVAL / EIO on stat. Skip and record once.
                other_errors.append(f"{candidate}: {e}")
                continue
            if is_file:
                scan_config_file(candidate, report)

        # Lockfiles at any project root (heuristic: same dir contains package.json).
        if "package.json" in filenames:
            for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                if lock in filenames:
                    scan_lockfile(dirpath / lock, report)

    # Summarise permission/IO errors so we don't flood the report.
    if perm_denied:
        sample = ", ".join(perm_denied[:3])
        more = f" (+{len(perm_denied) - 3} more)" if len(perm_denied) > 3 else ""
        report.add(
            SEVERITY_INFO,
            "scan",
            f"Skipped {len(perm_denied)} directories due to permission errors: {sample}{more}",
            str(root),
        )
    if other_errors:
        sample = "; ".join(other_errors[:3])
        more = f" (+{len(other_errors) - 3} more)" if len(other_errors) > 3 else ""
        report.add(
            SEVERITY_INFO,
            "scan",
            f"{len(other_errors)} I/O errors during walk: {sample}{more}",
            str(root),
        )


def scan_config_file(path: Path, report: Report) -> None:
    try:
        text = path.read_text(errors="replace")
    except PermissionError:
        return  # permission errors are summarised at end of scan
    except OSError as e:
        report.add(SEVERITY_INFO, "scan", f"Could not read {path}: {e}", str(path))
        return
    for pat in SUSPICIOUS_CONFIG_PATTERNS:
        m = pat.search(text)
        if m:
            report.add(
                SEVERITY_HIGH,
                "suspicious-config",
                f"{path.name} references IoC '{m.group(0)}'",
                str(path),
            )


def scan_lockfile(path: Path, report: Report) -> None:
    try:
        text = path.read_text(errors="replace")
    except PermissionError:
        return
    except OSError as e:
        report.add(SEVERITY_INFO, "scan", f"Could not read {path}: {e}", str(path))
        return

    # Generic IoC strings that have surfaced in compromised packages.
    for needle, label in [
        ("shai-hulud", "shai-hulud reference"),
        ("router_init", "router_init reference"),
        ("gh-token-monitor", "gh-token-monitor reference"),
        ("dependabout", "dependabout reference"),
    ]:
        if needle in text.lower():
            report.add(
                SEVERITY_HIGH,
                "lockfile-ioc",
                f"Lockfile contains {label} ('{needle}')",
                str(path),
            )

    # Heuristic time-window check: integrity entries resolved late Apr / May 2026.
    # We can't get exact resolution dates from the lockfile alone, so we just
    # flag the file for manual review if package.json or lockfile mtime falls
    # in that window.
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return
    # 2026-04-25 .. 2026-05-31 UTC
    if 1745539200 <= mtime <= 1748736000:
        report.add(
            SEVERITY_MED,
            "lockfile-window",
            "Lockfile mtime falls inside the Apr 29 / May 2026 attack window — "
            "review newly-added or version-bumped dependencies manually",
            str(path),
        )


# --- Process scan -------------------------------------------------------------

def scan_processes(report: Report) -> None:
    progress("[proc] checking running processes and LaunchAgents ...")
    if shutil.which("ps") is None:
        report.add(SEVERITY_INFO, "process", "`ps` not available — skipping process check")
        return
    try:
        out = subprocess.run(
            ["ps", "-Ao", "pid=,command="],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as e:
        report.add(SEVERITY_INFO, "process", f"Could not run ps: {e}")
        return

    for line in out.stdout.splitlines():
        line_l = line.lower()
        for name in SUSPICIOUS_PROCESS_NAMES:
            if name in line_l:
                report.add(SEVERITY_HIGH, "process", f"Suspicious process running: {line.strip()}")

    # Also check launchd / systemd unit files passively (read-only).
    if sys.platform == "darwin":
        for base in [Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]:
            if not base.is_dir():
                continue
            try:
                for p in base.iterdir():
                    if not p.is_file():
                        continue
                    try:
                        txt = p.read_text(errors="replace")
                    except OSError:
                        continue
                    for name in SUSPICIOUS_PROCESS_NAMES | {"shai-hulud"}:
                        if name in txt.lower():
                            report.add(
                                SEVERITY_HIGH,
                                "persistence",
                                f"LaunchAgent/Daemon references '{name}'",
                                str(p),
                            )
            except PermissionError:
                pass


# --- GitHub checks (optional, via gh CLI) -------------------------------------

def gh_available() -> bool:
    return shutil.which("gh") is not None


def gh_json(args: list[str]) -> object | None:
    try:
        out = subprocess.run(
            ["gh", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return None


def scan_github(report: Report) -> None:
    progress("[gh]   checking GitHub via gh CLI ...")
    if not gh_available():
        report.add(SEVERITY_INFO, "github", "`gh` CLI not installed — skipping GitHub checks")
        return

    # Identify the authenticated user.
    me = gh_json(["api", "user"])
    if not isinstance(me, dict) or "login" not in me:
        report.add(SEVERITY_INFO, "github", "`gh` is not authenticated — skipping GitHub checks")
        return
    login = me["login"]
    progress(f"[gh]   authenticated as {login}; listing repos ...")

    # 1. Repositories the user owns — look for Shai-Hulud names.
    repos = gh_json(["repo", "list", login, "--limit", "1000", "--json", "name,visibility,url"])
    repo_count = len(repos) if isinstance(repos, list) else 0
    progress(f"[gh]   {repo_count} repos found; scanning branches and artifacts ...")
    if isinstance(repos, list):
        for r in repos:
            name = str(r.get("name", "")).lower()
            if name in SUSPICIOUS_REPO_NAMES or "shai-hulud" in name:
                report.add(
                    SEVERITY_HIGH,
                    "github-repo",
                    f"Repository '{r.get('name')}' ({r.get('visibility')}) matches Shai-Hulud naming",
                    r.get("url", ""),
                )

    # 2. For each repo, check for dependabout/** branches and format-results artifacts.
    if isinstance(repos, list):
        for i, r in enumerate(repos[:200], 1):  # cap to avoid hammering the API
            full = f"{login}/{r.get('name')}"
            if i % 10 == 0:
                progress(f"[gh]     {i}/{min(repo_count, 200)} repos checked")
            branches = gh_json(["api", f"repos/{full}/branches", "--paginate"])
            if isinstance(branches, list):
                for b in branches:
                    bname = str(b.get("name", ""))
                    if bname.startswith(SUSPICIOUS_BRANCH_PREFIX):
                        report.add(
                            SEVERITY_HIGH,
                            "github-branch",
                            f"Branch '{bname}' in {full} matches dependabout/** pattern",
                            f"https://github.com/{full}/tree/{bname}",
                        )
            artifacts = gh_json(["api", f"repos/{full}/actions/artifacts", "--paginate"])
            if isinstance(artifacts, dict):
                for a in artifacts.get("artifacts", []):
                    aname = str(a.get("name", "")).lower()
                    if aname in SUSPICIOUS_ARTIFACT_NAMES:
                        report.add(
                            SEVERITY_HIGH,
                            "github-artifact",
                            f"Workflow artifact '{a.get('name')}' in {full} matches IoC",
                            a.get("archive_download_url", ""),
                        )


# --- Reporting ----------------------------------------------------------------

def print_report(report: Report) -> int:
    order = {SEVERITY_HIGH: 0, SEVERITY_MED: 1, SEVERITY_INFO: 2}
    report.findings.sort(key=lambda f: (order.get(f.severity, 3), f.category))

    print()
    print("=" * 72)
    print("Mini Shai-Hulud audit report")
    print("=" * 72)
    print(f"Scanned roots: {', '.join(report.scanned_roots) or '(none)'}")
    print(f"Files inspected: {report.files_scanned}")
    print()

    high = [f for f in report.findings if f.severity == SEVERITY_HIGH]
    med = [f for f in report.findings if f.severity == SEVERITY_MED]
    info = [f for f in report.findings if f.severity == SEVERITY_INFO]

    def render(group: list[Finding], label: str) -> None:
        print(f"--- {label} ({len(group)}) ---")
        if not group:
            print("  (none)")
        for f in group:
            loc = f"  -> {f.location}" if f.location else ""
            print(f"  [{f.category}] {f.message}{loc}")
        print()

    render(high, "HIGH severity")
    render(med, "MED severity")
    render(info, "INFO / scan notes")

    print("=" * 72)
    if high:
        print("RESULT: HIGH-severity indicators present. DO NOT revoke tokens yet —")
        print("the worm has a reported dead-man's-switch. Isolate the machine from")
        print("the network first, then plan remediation from a clean environment.")
        return 2
    if med:
        print("RESULT: Some suspicious signals found. Manual review recommended.")
        return 1
    print("RESULT: No indicators of Mini Shai-Hulud found in the scanned scope.")
    return 0


# --- Entry point --------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("roots", nargs="*", help="Paths to scan (default: $HOME)")
    parser.add_argument("--no-github", action="store_true", help="Skip gh CLI checks")
    parser.add_argument("--no-processes", action="store_true", help="Skip process / LaunchAgent checks")
    args = parser.parse_args()

    roots = [Path(r) for r in args.roots] or [Path.home()]
    report = Report(scanned_roots=[str(r) for r in roots])

    for root in roots:
        scan_filesystem(root, report)
    progress_clear()

    if not args.no_processes:
        scan_processes(report)

    if not args.no_github:
        scan_github(report)

    progress_clear()
    return print_report(report)


if __name__ == "__main__":
    sys.exit(main())
