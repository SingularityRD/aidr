#!/usr/bin/env python3
"""Record raw licence evidence for every wheel in a hash-locked PyPI runtime set.

Reads a `uv pip compile --generate-hashes` lock plus a directory of the wheels it
pins (for example `pip download --require-hashes --no-deps --only-binary=:all:
--platform manylinux2014_x86_64 --python-version 3.12 -r <lock> -d <dir>`), checks
each wheel's SHA-256 against the lock, and writes the Core Metadata licence
fields, the licence files shipped in `*.dist-info`, and any bundled native
libraries (`*.libs/`) as deterministic JSON.

It records evidence only. Mapping that evidence to SPDX and an obligation class
happens in scripts/lib/pypi-license-data.mjs, which refuses to guess.

Usage:
  python scripts/extract-pypi-license-metadata.py --lock services/aig-bridge/requirements-runtime.lock \
      --wheels <dir> --output services/aig-bridge/pypi-runtime-licenses.json

The privacy worker locks have their own evidence files, listed with their
platform in scripts/lib/python-sbom-components.mjs (PRIVACY_PYTHON_SOURCES),
e.g. --lock packages/privacy/parsers/requirements.lock.txt
--output packages/privacy/sbom/parsers.pypi-licenses.json. Download the NER
torch wheels with --extra-index-url https://download.pytorch.org/whl/cpu.
"""

import argparse
import email
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(text: str) -> dict:
    packages: dict = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        digest = re.fullmatch(r"--hash=sha256:([a-f0-9]{64})", line)
        if digest:
            current["hashes"].add(digest.group(1))
            continue
        # Hashes may also sit on the pin line (compact privacy worker locks).
        requirement, *options = line.split()
        pin = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", requirement)
        inline = [re.fullmatch(r"--hash=sha256:([a-f0-9]{64})", option) for option in options]
        if not pin or not all(inline):
            raise SystemExit(f"unsupported lock entry: {line[:80]}")
        current = {"name": canonical(pin.group(1)), "version": pin.group(2), "hashes": {m.group(1) for m in inline}}
        packages[current["name"]] = current
    return packages


def inspect_wheel(path: Path) -> dict:
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        metadata_name = next(n for n in names if re.fullmatch(r"[^/]+\.dist-info/METADATA", n))
        message = email.message_from_bytes(wheel.read(metadata_name))
        dist_info = metadata_name.rsplit("/", 1)[0] + "/"
        license_files = []
        for name in sorted(names):
            if not name.startswith(dist_info) or name.endswith("/"):
                continue
            relative = name[len(dist_info):]
            if re.search(r"(^|/)(licen[cs]e|copying|notice|authors)[^/]*$", relative, re.I):
                license_files.append({"path": relative, "sha256": hashlib.sha256(wheel.read(name)).hexdigest()})
        bundled = sorted(n for n in names if re.search(r"\.libs/[^/]+$", n))
    field = (message.get("License") or "").strip()
    return {
        "wheel": path.name,
        "wheel_sha256": sha,
        "core_metadata": {
            "license_expression": (message.get("License-Expression") or "").strip() or None,
            "license_field": field if field and "\n" not in field and len(field) <= 200 else (None if not field else "<multi-line licence text>"),
            "license_classifiers": sorted(c for c in (message.get_all("Classifier") or []) if c.startswith("License ::")),
            "license_file_headers": sorted(message.get_all("License-File") or []),
        },
        "license_files": license_files,
        "bundled_native_libraries": bundled,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True)
    parser.add_argument("--wheels", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    lock = parse_lock(Path(args.lock).read_text(encoding="utf-8"))
    found: dict = {}
    for wheel_path in sorted(Path(args.wheels).glob("*.whl")):
        record = inspect_wheel(wheel_path)
        stem = wheel_path.name.split("-")
        name = canonical(stem[0])
        if name not in lock:
            raise SystemExit(f"wheel {wheel_path.name} is not in the lock")
        if record["wheel_sha256"] not in lock[name]["hashes"]:
            raise SystemExit(f"wheel {wheel_path.name} does not match any locked SHA-256")
        if stem[1] != lock[name]["version"]:
            raise SystemExit(f"wheel {wheel_path.name} version differs from the lock")
        found[name] = {"name": name, "version": lock[name]["version"], **record}
    missing = sorted(set(lock) - set(found))
    if missing:
        raise SystemExit(f"no wheel for locked packages: {', '.join(missing)}")

    lock_sha = hashlib.sha256(Path(args.lock).read_bytes()).hexdigest()
    output = {
        "schema_version": 1,
        "source_lock": Path(args.lock).as_posix(),
        "source_lock_sha256": lock_sha,
        "evidence_origin": "Core Metadata and dist-info licence files read from the SHA-256-verified wheels pinned by the lock",
        "packages": [found[name] for name in sorted(found)],
    }
    Path(args.output).write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.output}: {len(found)} packages")


if __name__ == "__main__":
    sys.exit(main())
