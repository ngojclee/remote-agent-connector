"""Classify whether a push can change a published image.

This repository publishes two images that Watchtower tracks: the connector
``:latest`` and the WSS relay ``:relay-latest``. A commit that only edits
documentation, tests or fixtures cannot change either one, so publishing for it
restarts the relay and drops live device connections for no reason.

The rule is conservative in one direction only: anything the classifier cannot
explain is treated as runtime, so a path filter can never silently swallow a
real code change.

The lists below mirror what ``Dockerfile`` and ``deploy/Dockerfile.relay``
actually copy into the images.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

RUNTIME_PREFIXES: tuple[str, ...] = (
    "remote_agent_connector/",
    # The relay image is built from deploy/Dockerfile.relay and bakes
    # deploy/remote-agent-relay.nginx.conf, so the whole directory is runtime.
    "deploy/",
)
RUNTIME_FILES: tuple[str, ...] = (
    "Dockerfile",
    "README.md",
    "pyproject.toml",
    ".dockerignore",
)

ZERO_SHA = "0000000000000000000000000000000000000000"


def is_runtime_path(path: str) -> bool:
    raw = str(path or "").strip()
    # Only a leading "./" or "/" is removed. lstrip("./") would also eat the
    # dot in a dotfile such as .dockerignore and misclassify it.
    normalized = raw[2:] if raw.startswith("./") else raw
    normalized = normalized.lstrip("/")
    if not normalized:
        return True
    if normalized in RUNTIME_FILES:
        return True
    if any(normalized.startswith(prefix) for prefix in RUNTIME_PREFIXES):
        return True
    # A bare directory name with no trailing slash still names a runtime tree.
    return any(
        normalized + "/" == prefix for prefix in RUNTIME_PREFIXES
    )


def classify(paths: list[str]) -> tuple[bool, list[str]]:
    hits = sorted({path for path in paths if is_runtime_path(path)})
    return bool(hits), hits


def changed_paths(base: str, head: str) -> list[str]:
    completed = subprocess.run(
        ["git", "diff", "--name-only", f"{base}..{head}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "git diff failed")
    return [line for line in completed.stdout.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="")
    parser.add_argument(
        "--path",
        action="append",
        default=[],
        help="classify explicit paths instead of a git range",
    )
    args = parser.parse_args(argv)

    base = (args.base or "").strip()
    head = (args.head or "").strip()
    if args.path:
        paths = list(args.path)
        reason = "explicit-paths"
    elif not base or base == ZERO_SHA or not head:
        print("runtime=true")
        print("reason=base-unknown")
        return 0
    else:
        try:
            paths = changed_paths(base=base, head=head)
        except ValueError as exc:
            print(f"error={exc}", file=sys.stderr)
            print("runtime=true")
            print("reason=diff-failed")
            return 0
        reason = "git-range"

    runtime, hits = classify(paths)
    print(f"runtime={'true' if runtime else 'false'}")
    print(f"reason={reason}")
    print(f"changed={len(paths)}")
    for hit in hits:
        print(f"runtime_path={hit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
