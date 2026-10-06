"""Stdlib fixture checks; no real wheel code is imported or executed."""
import hashlib
import importlib.util
import json
import runpy
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("notice_archive", ROOT / "archive-pypi-license-materials.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NoticeArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aidr-notice-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wheel = self.root / "example-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(self.wheel, "w") as wheel:
            wheel.writestr("example-1.0.0.dist-info/METADATA", "Name: example\nVersion: 1.0.0\nLicense: MIT\nLicense-File: LICENSE\n")
            wheel.writestr("example-1.0.0.dist-info/LICENSE", "Fixture licence text\n")
            wheel.writestr("example.libs/library.so", b"fixture bytes only")
        lock = self.root / "requirements.lock"
        lock.write_text(f"example==1.0.0 \\\n    --hash=sha256:{hashlib.sha256(self.wheel.read_bytes()).hexdigest()}\n", encoding="utf8")
        inspect = runpy.run_path(str(ROOT / "extract-pypi-license-metadata.py"))["inspect_wheel"]
        self.manifest_data = {"source_lock": str(lock), "source_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(), "packages": [{"name": "example", "version": "1.0.0", **inspect(self.wheel)}]}
        self.manifest = self.root / "manifest.json"
        self.write_manifest()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.manifest_data), encoding="utf8")

    def test_exact_materials_remain_unaccepted(self):
        output = self.root / "review"
        module.archive(self.manifest, self.root, output)
        inventory = json.loads((output / "inventory.json").read_text())
        self.assertEqual(inventory["status"], "OPEN_REVIEW_INPUT_NOT_ACCEPTED")
        record = inventory["packages"][0]
        for notice in record["license_files"]:
            self.assertEqual(hashlib.sha256((output / notice["path"]).read_bytes()).hexdigest(), notice["sha256"])
        self.assertEqual(record["native_libraries"][0]["sha256"], hashlib.sha256(b"fixture bytes only").hexdigest())
        self.assertEqual(record["native_libraries"][0]["independent_license_terms"], "unknown")
        self.assertIsNone(record["native_libraries"][0]["elf_class"])

    def test_tamper_stops_before_output(self):
        for key in ("wheel_sha256", "license_files"):
            original = self.manifest_data["packages"][0][key]
            self.manifest_data["packages"][0][key] = "0" * 64 if key == "wheel_sha256" else []
            self.write_manifest()
            output = self.root / f"invalid-{key}"
            with self.assertRaises(ValueError):
                module.archive(self.manifest, self.root, output)
            self.assertFalse(output.exists())
            self.manifest_data["packages"][0][key] = original

    def test_no_overwrite_or_traversal(self):
        output = self.root / "existing"
        output.mkdir()
        sentinel = output / "retained.txt"
        sentinel.write_text("existing evidence", encoding="utf8")
        with self.assertRaises(FileExistsError):
            module.archive(self.manifest, self.root, output)
        self.assertEqual(sentinel.read_text(), "existing evidence")
        for member in ("../outside", "/absolute", "C:/outside", "a\\b"):
            with self.assertRaises(ValueError):
                module.safe_relative(member)

    def test_system_notice_bytes_are_verified_without_granting_approval(self):
        notice = self.root / "distro-notices" / "fixture-copyright"
        notice.parent.mkdir()
        notice.write_bytes(b"Actual fixture copyright text\n")
        native = self.root / "native-runtime-inventory.json"
        native.write_text(json.dumps({"scope": "fixture runtime paths only", "libraries": [{"path": "/usr/lib/fixture.so", "sha256": "a" * 64, "owner": "fixture:amd64", "package_version": "1.0"}], "notice_materials": [{"file": "distro-notices/fixture-copyright", "sha256": hashlib.sha256(notice.read_bytes()).hexdigest()}]}), encoding="utf8")
        output = self.root / "system-review"
        module.archive(self.manifest, self.root, output, native)
        self.assertEqual((output / "distro-notices/fixture-copyright").read_bytes(), notice.read_bytes())
        receipt = json.loads((output / "inventory.json").read_text())
        self.assertEqual(receipt["system_native_inventory"]["status"], "OPEN_REVIEW_INPUT_NOT_ACCEPTED")
        notice.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            module.archive(self.manifest, self.root, self.root / "tampered-system", native)
        self.assertFalse((self.root / "tampered-system").exists())


if __name__ == "__main__":
    unittest.main()
