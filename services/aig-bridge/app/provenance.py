"""Verification of the signed, immutable AIG dataset release."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


_ARTIFACT_NAMES = (
    "aig-cve-index.json",
    "aig-fingerprints.json",
    "aig-mcp-categories.json",
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")


@dataclass(frozen=True)
class DatasetProvenance:
    ready: bool
    reason: str
    bundle_id: str | None = None
    source_commit: str | None = None
    release_sequence: int | None = None


def _failed(reason: str) -> DatasetProvenance:
    return DatasetProvenance(False, reason)


def _canonical_json(value: object) -> bytes:
    # Matches JSON.stringify used by scripts/compile-aig-data.mjs.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_dataset_provenance(
    threats: Mapping[str, object] | None,
    upstream_provenance: Mapping[str, object] | None,
) -> DatasetProvenance:
    """Verify the signed bundle and matching authenticated upstream evidence."""

    manifest_value = os.getenv("AIG_DATA_MANIFEST_PATH", "").strip()
    public_key_value = os.getenv("AIG_SIGNING_PUBLIC_KEY_PATH", "").strip()
    trusted_key_id = os.getenv("AIG_TRUSTED_SIGNING_KEY_ID", "").strip()
    trusted_fingerprint = os.getenv(
        "AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256", ""
    ).strip().lower()
    expected_bundle = os.getenv("AIG_EXPECTED_DATA_BUNDLE_ID", "").strip().lower()
    expected_commit = os.getenv("AIG_EXPECTED_SOURCE_COMMIT", "").strip().lower()
    if not all(
        [
            manifest_value,
            public_key_value,
            trusted_key_id,
            trusted_fingerprint,
            expected_bundle,
            expected_commit,
        ]
    ):
        return _failed("AIG dataset trust policy is incomplete")
    if (
        not _SHA256_RE.fullmatch(trusted_fingerprint)
        or not _SHA256_RE.fullmatch(expected_bundle)
        or not _COMMIT_RE.fullmatch(expected_commit)
    ):
        return _failed("AIG dataset trust policy is invalid")

    manifest_path = Path(manifest_value)
    public_key_path = Path(public_key_value)
    if not manifest_path.is_absolute() or not public_key_path.is_absolute():
        return _failed("AIG dataset trust paths must be absolute")

    try:
        if manifest_path.is_symlink() or public_key_path.is_symlink():
            return _failed("AIG dataset trust files must not be symbolic links")
        manifest_bytes = manifest_path.read_bytes()
        if len(manifest_bytes) > 1024 * 1024:
            return _failed("AIG data manifest exceeds the size limit")
        manifest = json.loads(manifest_bytes)
        if not isinstance(manifest, dict):
            return _failed("AIG data manifest is invalid")
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _failed("AIG data manifest is unavailable or invalid")

    release_sequence = manifest.get("release_sequence")
    source = manifest.get("source")
    counts = manifest.get("counts")
    artifacts = manifest.get("artifacts")
    runtime = manifest.get("runtime")
    bundle_id = manifest.get("bundle_id")
    source_commit = source.get("commit") if isinstance(source, dict) else None
    source_tree = source.get("tree_sha256") if isinstance(source, dict) else None
    if (
        manifest.get("schema") != "aig-data-manifest/v1"
        or isinstance(release_sequence, bool)
        or not isinstance(release_sequence, int)
        or release_sequence < 1
        or not isinstance(bundle_id, str)
        or not _SHA256_RE.fullmatch(bundle_id)
        or not isinstance(source_commit, str)
        or not _COMMIT_RE.fullmatch(source_commit)
        or not isinstance(source_tree, str)
        or not _SHA256_RE.fullmatch(source_tree)
        or not isinstance(counts, dict)
        or not isinstance(artifacts, dict)
        or not isinstance(runtime, dict)
        or runtime.get("schema") != "aig-runtime-data/v1"
        or runtime.get("root") != "data"
        or not isinstance(runtime.get("tree_sha256"), str)
        or not _SHA256_RE.fullmatch(runtime["tree_sha256"])
        or isinstance(runtime.get("files"), bool)
        or not isinstance(runtime.get("files"), int)
        or runtime["files"] <= 0
        or isinstance(runtime.get("bytes"), bool)
        or not isinstance(runtime.get("bytes"), int)
        or runtime["bytes"] <= 0
    ):
        return _failed("AIG data manifest schema is invalid")
    if bundle_id != expected_bundle or source_commit != expected_commit:
        return _failed("AIG data manifest does not match the deployment pin")

    artifact_root = manifest_path.parent.resolve()
    verified_artifacts: dict[str, object] = {}
    try:
        for name in _ARTIFACT_NAMES:
            expected = artifacts.get(name)
            if not isinstance(expected, dict):
                return _failed("AIG data manifest artifact registry is incomplete")
            expected_hash = expected.get("sha256")
            expected_bytes = expected.get("bytes")
            if (
                not isinstance(expected_hash, str)
                or not _SHA256_RE.fullmatch(expected_hash)
                or isinstance(expected_bytes, bool)
                or not isinstance(expected_bytes, int)
                or expected_bytes <= 0
            ):
                return _failed("AIG data manifest artifact metadata is invalid")
            artifact_path = manifest_path.parent / name
            resolved = artifact_path.resolve(strict=True)
            if (
                artifact_path.is_symlink()
                or not resolved.is_relative_to(artifact_root)
                or not resolved.is_file()
                or resolved.stat().st_size != expected_bytes
                or _sha256_file(resolved) != expected_hash
            ):
                return _failed("AIG data artifact digest verification failed")
            verified_artifacts[name] = expected
    except OSError:
        return _failed("AIG data artifacts are unavailable")

    calculated_bundle = hashlib.sha256(_canonical_json(verified_artifacts)).hexdigest()
    if calculated_bundle != bundle_id:
        return _failed("AIG data manifest bundle digest is invalid")

    signature = manifest.get("signature")
    if (
        not isinstance(signature, dict)
        or signature.get("algorithm") != "RSA-SHA256"
        or signature.get("key_id") != trusted_key_id
        or not isinstance(signature.get("value"), str)
    ):
        return _failed("AIG data manifest signature policy failed")
    try:
        public_key_bytes = public_key_path.read_bytes()
        if len(public_key_bytes) > 64 * 1024:
            return _failed("AIG data manifest public key exceeds the size limit")
        public_key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
            return _failed("AIG data manifest public key must be RSA with at least 2048 bits")
        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if hashlib.sha256(public_der).hexdigest() != trusted_fingerprint:
            return _failed("AIG data manifest public key is not trusted")
        payload = dict(manifest)
        del payload["signature"]
        public_key.verify(
            base64.b64decode(signature["value"], validate=True),
            _canonical_json(payload),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (OSError, ValueError, TypeError, InvalidSignature):
        return _failed("AIG data manifest signature verification failed")

    live_cves = threats.get("cve_count") if threats else None
    live_categories = threats.get("mcp_risk_categories") if threats else None
    manifest_cves = counts.get("cves")
    manifest_categories = counts.get("mcp_categories")
    if (
        isinstance(manifest_cves, bool)
        or not isinstance(manifest_cves, int)
        or manifest_cves <= 0
        or isinstance(manifest_categories, bool)
        or not isinstance(manifest_categories, int)
        or manifest_categories <= 0
    ):
        return _failed("AIG data manifest counts are invalid")
    if (
        isinstance(live_cves, bool)
        or not isinstance(live_cves, int)
        or live_cves <= 0
        or not isinstance(live_categories, list)
        or not live_categories
    ):
        return _failed("live AIG datasets are empty or invalid")

    if not upstream_provenance or upstream_provenance.get("verified") is not True:
        return _failed("authenticated AIG dataset provenance is unavailable")
    if (
        upstream_provenance.get("bundle_id") != bundle_id
        or upstream_provenance.get("source_commit") != source_commit
        or upstream_provenance.get("release_sequence") != release_sequence
    ):
        return _failed("authenticated AIG dataset provenance does not match the signed manifest")

    return DatasetProvenance(
        True,
        "live AIG datasets match authenticated signed provenance",
        bundle_id=bundle_id,
        source_commit=source_commit,
        release_sequence=release_sequence,
    )
