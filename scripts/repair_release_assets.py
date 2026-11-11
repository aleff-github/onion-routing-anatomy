#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Normalize already-published translation release assets to portable ASCII names.

GitHub silently sanitizes non-ASCII upload basenames, breaking SHA256SUMS.
This process preserves release tags and commit history and repairs only the
three translated releases that were uploaded with Unicode filenames.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from publish_translated_releases import (
    EDITIONS, REPOSITORY, ROOT, command, preflight, stage_files,
)

TARGET_LANGUAGES = {"es", "ru", "zh-Hans"}
UNCHANGED_NAMES = {"LICENSE", "NOTICE.md"}


def inspect(tag: str) -> set[str]:
    info = json.loads(command(
        "gh", "release", "view", tag, "--repo", REPOSITORY,
        "--json", "assets,isDraft",
    ).stdout)
    if info["isDraft"]:
        raise RuntimeError(f"Non modificare release draft: {tag}")
    return {asset["name"] for asset in info["assets"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Repair GitHub assets")
    args = parser.parse_args()
    _head, releases = preflight()
    for edition in EDITIONS:
        lang = edition[0]
        if lang not in TARGET_LANGUAGES:
            continue
        tag = f"v1.0.0-{lang}"
        if tag not in releases:
            raise RuntimeError(f"Release non trovata: {tag}")
        with tempfile.TemporaryDirectory(prefix="onion-repair-") as tmp:
            assets = stage_files(Path(tmp), edition)
            expected = {path.name for path in assets}
            existing = inspect(tag)
            obsolete = existing - expected
            missing = expected - existing
            if not args.apply:
                print(f"{tag}: obsolete={sorted(obsolete)}, missing={sorted(missing)}")
                continue
            # Remove only names absent from the corrected release package.
            for old in sorted(obsolete):
                command(
                    "gh", "release", "delete-asset", "--yes", "--repo", REPOSITORY,
                    "--", tag, old,
                )
                print(f"{tag}: removed sanitized asset {old!r}")

            # Upload corrected assets, including checksum and translated notes.
            # LICENSE and NOTICE.md are already identical and need no replacement.
            for path in assets:
                if path.name in UNCHANGED_NAMES and path.name in existing:
                    continue
                options = ["--clobber"] if path.name in existing else []
                command(
                    "gh", "release", "upload", tag, str(path),
                    "--repo", REPOSITORY, *options,
                )
                print(f"{tag}: uploaded {path.name}")

            # Change the visible release description to match ASCII asset names.
            command(
                "gh", "release", "edit", tag,
                "--repo", REPOSITORY,
                "--notes-file", str(ROOT / "docs" / "releases" / f"{tag}.md"),
            )
            final = inspect(tag)
            if final != expected:
                raise RuntimeError(
                    f"{tag}: mismatch, missing={sorted(expected-final)}, "
                    f"unexpected={sorted(final-expected)}"
                )
            print(f"{tag}: OK, {len(final)} correctly named assets")
    if not args.apply:
        print("Preview only. To repair, rerun with --apply.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        print(f"ERRORE: {error}", file=sys.stderr)
        sys.exit(1)
