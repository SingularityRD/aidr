#!/usr/bin/env python3
"""Offline review archive from exact locked wheels; never executes/imports a wheel.

Usage: python scripts/archive-pypi-license-materials.py --wheels DIR --output NEW_DIR
       [--manifest services/aig-bridge/pypi-runtime-licenses.json]
       [--native-inventory PATH_TO_BUILT_IMAGE_INVENTORY.json]
The output contains actual licence texts and native byte inventories. It is not
a Legal decision, source offer, image SBOM, binary security scan or release GO.
"""
import argparse
import hashlib
import json
import re
import runpy
import struct
import zipfile
from pathlib import Path, PurePosixPath


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_relative(name):
    value = PurePosixPath(name)
    if value.is_absolute() or ".." in value.parts or "\\" in name or ":" in name:
        raise ValueError("unsafe archive member")
    return value


def prepare_native_inventory(path):
    if path is None:
        return None
    data = path.read_bytes()
    inventory = json.loads(data)
    if not inventory.get("libraries") or not inventory.get("notice_materials"):
        raise ValueError("native inventory must name actual library paths and notice materials")
    for library in inventory["libraries"]:
        if not library["path"].startswith("/") or not re.fullmatch(r"[0-9a-f]{64}", library["sha256"]) or not library.get("owner") or not library.get("package_version"):
            raise ValueError("native library must identify an absolute runtime path, digest and package version")
    notices = []
    seen = set()
    for record in inventory["notice_materials"]:
        relative = safe_relative(record["file"])
        if relative.as_posix() in seen:
            raise ValueError("duplicate native notice path")
        seen.add(relative.as_posix())
        source = path.parent / relative
        if not source.resolve().is_relative_to(path.parent.resolve()):
            raise ValueError("native notice must stay inside its inventory folder")
        material = source.read_bytes()
        if sha(material) != record["sha256"]:
            raise ValueError("native notice digest differs from built-image inventory")
        notices.append((relative, material))
    return data, inventory, notices


def archive(manifest_path, wheels, output, native_inventory_path=None):
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    lock_path = Path(manifest["source_lock"])
    if sha(lock_path.read_bytes()) != manifest["source_lock_sha256"]:
        raise ValueError("manifest does not match the current source lock")
    extractor = runpy.run_path(str(Path(__file__).with_name("extract-pypi-license-metadata.py")))
    locked = extractor["parse_lock"](lock_path.read_text(encoding="utf8"))
    if {p["name"] for p in manifest["packages"]} != set(locked):
        raise ValueError("manifest must cover every locked package")
    prepared = []
    for package in manifest["packages"]:
        path = wheels / safe_relative(package["wheel"])
        inspected = extractor["inspect_wheel"](path)
        if inspected["wheel_sha256"] != package["wheel_sha256"] or inspected["wheel_sha256"] not in locked[package["name"]]["hashes"] or package["version"] != locked[package["name"]]["version"]:
            raise ValueError("wheel/version differs from the locked manifest")
        if inspected["license_files"] != package["license_files"] or inspected["bundled_native_libraries"] != package["bundled_native_libraries"]:
            raise ValueError("wheel licence/native inventory differs from manifest")
        prepared.append((package, path))
    native = prepare_native_inventory(native_inventory_path)
    output.mkdir(parents=True, exist_ok=False)  # never overwrites review evidence
    (output / "source-manifest.json").write_bytes(manifest_bytes)
    (output / "source-lock.txt").write_bytes(lock_path.read_bytes())
    records = []
    for package, path in prepared:
        record = {"name": package["name"], "version": package["version"], "wheel": package["wheel"], "wheel_sha256": package["wheel_sha256"], "license_files": [], "native_libraries": []}
        with zipfile.ZipFile(path) as wheel:
            prefix = next(name.rsplit("/", 1)[0] for name in wheel.namelist() if re.fullmatch(r"[^/]+\.dist-info/METADATA", name))
            for license_file in package["license_files"]:
                data = wheel.read(f"{prefix}/{license_file['path']}")
                if sha(data) != license_file["sha256"]:
                    raise ValueError("licence text digest differs from manifest")
                relative = PurePosixPath("wheels") / f"{package['name']}-{package['version']}" / safe_relative(license_file["path"])
                target = output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                record["license_files"].append({"path": relative.as_posix(), "sha256": sha(data), "bytes": len(data)})
            for name in package["bundled_native_libraries"]:
                data = wheel.read(safe_relative(name).as_posix())
                indicators = sorted(set(s.decode("ascii") for s in re.findall(rb"[ -~]{6,}", data) if re.search(rb"OpenSSL [0-9]|^[0-9]+\.[0-9]+ [12][0-9]{3}-[01][0-9]-[0-3][0-9]$", s)))
                elf = data[:4] == b"\x7fELF"
                record["native_libraries"].append({"path": name, "sha256": sha(data), "bytes": len(data), "elf_class": data[4] if elf else None, "elf_machine": struct.unpack("<H", data[18:20])[0] if elf and data[5] == 1 else None, "embedded_version_indicators": indicators, "exact_source_version": "unknown", "independent_license_terms": "unknown", "review_status": "open"})
        records.append(record)
    inventory = {"schema": "aidr.pypi-notice-review-archive.v1", "status": "OPEN_REVIEW_INPUT_NOT_ACCEPTED", "manifest_sha256": sha(manifest_bytes), "source_lock_sha256": manifest["source_lock_sha256"], "packages": records, "limitations": ["Exact locked wheel and shipped licence-text bytes only; no wheel execution/import", "Native byte identities are exact; embedded strings are indicators, not publisher source attestation or a licence conclusion", "Full container/base-image/OS and alternate platform inventories are excluded; any attached system inventory covers only its stated runtime paths", "Common-license text availability does not mean every listed license applies to a library; package copyright records require review", "No approved candidate, Legal disposition or binary security clearance is created"]}
    if native:
        data, runtime, notices = native
        (output / "native-runtime-inventory.json").write_bytes(data)
        for relative, material in notices:
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(material)
        inventory["system_native_inventory"] = {"path": "native-runtime-inventory.json", "sha256": sha(data), "scope": runtime.get("scope"), "libraries": len(runtime["libraries"]), "notice_materials": len(notices), "status": "OPEN_REVIEW_INPUT_NOT_ACCEPTED"}
    (output / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf8")
    (output / "README.txt").write_text("OPEN / REVIEW INPUT ONLY\nActual licence texts extracted from exact locked wheel bytes. Native terms/origins, current security disposition, container/upstream notice and source obligations require separate evidence and Legal review. No candidate accepted.\n", encoding="utf8")
    native_count = sum(len(p["native_libraries"]) for p in records)
    text_count = sum(len(p["license_files"]) for p in records)
    system_count = len(native[1]["libraries"]) if native else 0
    system_texts = len(native[2]) if native else 0
    print(f"REVIEW_ARCHIVE_WRITTEN: {len(records)} wheels, {text_count} wheel licence texts, {native_count} wheel-native byte inventories, {system_count} system runtime paths, {system_texts} system notice texts; Legal/security/candidate acceptance OPEN")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="services/aig-bridge/pypi-runtime-licenses.json")
    parser.add_argument("--wheels", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--native-inventory")
    args = parser.parse_args()
    archive(Path(args.manifest), Path(args.wheels), Path(args.output), Path(args.native_inventory) if args.native_inventory else None)
