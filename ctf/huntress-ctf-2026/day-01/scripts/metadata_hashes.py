#!/usr/bin/env python3
"""Report a file's size and common digests from a ZIP archive."""

import argparse
import hashlib
import json
import pathlib
import zipfile


def main():
    parser = argparse.ArgumentParser(
        description="Read a ZIP member and print its filename, size, and hashes."
    )
    parser.add_argument("archive", type=pathlib.Path, help="path to the ZIP archive")
    parser.add_argument(
        "member",
        nargs="?",
        default="evidence-note.txt",
        help="member name or base filename (default: evidence-note.txt)",
    )
    args = parser.parse_args()

    with zipfile.ZipFile(args.archive) as archive:
        matches = [
            info
            for info in archive.infolist()
            if not info.is_dir()
            and (
                info.filename == args.member
                or pathlib.PurePosixPath(info.filename).name == args.member
            )
        ]
        if len(matches) != 1:
            raise SystemExit(
                f"Expected one ZIP member matching {args.member!r}; found {len(matches)}."
            )

        member = matches[0]
        content = archive.read(member)

    result = {
        "filename": pathlib.PurePosixPath(member.filename).name,
        "size_bytes": len(content),
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
