import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.provenance import verify_dataset_provenance


ARTIFACTS = {
    "aig-cve-index.json": b'{"cves":[{"id":"CVE-TEST"}]}',
    "aig-fingerprints.json": b'{"fingerprints":[{"name":"test"}]}',
    "aig-mcp-categories.json": b'{"categories":[{"id":"mcp-01"}]}',
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def _signed_fixture(tmp_path, monkeypatch):
    artifact_metadata = {}
    for name, contents in ARTIFACTS.items():
        (tmp_path / name).write_bytes(contents)
        artifact_metadata[name] = {
            "sha256": hashlib.sha256(contents).hexdigest(),
            "bytes": len(contents),
        }
    bundle_id = hashlib.sha256(_canonical(artifact_metadata)).hexdigest()
    source_commit = "b" * 40
    payload = {
        "schema": "aig-data-manifest/v1",
        "generated": "2026-09-22T00:00:00.000Z",
        "release_sequence": 7,
        "source": {
            "repository": "https://github.com/tencent/AI-Infra-Guard",
            "commit": source_commit,
            "tree_sha256": "c" * 64,
        },
        "bundle_id": bundle_id,
        "artifacts": artifact_metadata,
        "counts": {"cves": 1, "fingerprints": 1, "mcp_categories": 1},
        "runtime": {
            "schema": "aig-runtime-data/v1",
            "root": "data",
            "tree_sha256": "d" * 64,
            "files": 1,
            "bytes": 13,
        },
    }
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    signature = private_key.sign(
        _canonical(payload), padding.PKCS1v15(), hashes.SHA256()
    )
    manifest = {
        **payload,
        "signature": {
            "algorithm": "RSA-SHA256",
            "key_id": "release-key-7",
            "value": base64.b64encode(signature).decode(),
        },
    }
    manifest_path = tmp_path / "aig-data-manifest.json"
    manifest_path.write_text(_canonical(manifest).decode(), encoding="utf-8")
    for name, value in {
        "AIG_DATA_MANIFEST_PATH": str(manifest_path),
        "AIG_SIGNING_PUBLIC_KEY_PATH": str(public_path),
        "AIG_TRUSTED_SIGNING_KEY_ID": "release-key-7",
        "AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256": hashlib.sha256(public_der).hexdigest(),
        "AIG_EXPECTED_DATA_BUNDLE_ID": bundle_id,
        "AIG_EXPECTED_SOURCE_COMMIT": source_commit,
    }.items():
        monkeypatch.setenv(name, value)
    return manifest_path, {
        "verified": True,
        "bundle_id": bundle_id,
        "source_commit": source_commit,
        "release_sequence": 7,
    }


def test_signed_manifest_binds_live_dataset_counts(tmp_path, monkeypatch):
    _, upstream = _signed_fixture(tmp_path, monkeypatch)

    result = verify_dataset_provenance(
        {"cve_count": 1, "mcp_risk_categories": [{"id": "mcp-01"}]},
        upstream,
    )

    assert result.ready is True
    assert result.release_sequence == 7
    assert result.bundle_id == os.environ["AIG_EXPECTED_DATA_BUNDLE_ID"]


def test_unsigned_manifest_fails_closed(tmp_path, monkeypatch):
    manifest_path, upstream = _signed_fixture(tmp_path, monkeypatch)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["signature"] = None
    manifest_path.write_text(_canonical(manifest).decode(), encoding="utf-8")

    result = verify_dataset_provenance(
        {"cve_count": 1, "mcp_risk_categories": [{"id": "mcp-01"}]},
        upstream,
    )

    assert result.ready is False
    assert "signature" in result.reason


def test_tampered_artifact_fails_closed(tmp_path, monkeypatch):
    _, upstream = _signed_fixture(tmp_path, monkeypatch)
    (tmp_path / "aig-cve-index.json").write_bytes(b"tampered")

    result = verify_dataset_provenance(
        {"cve_count": 1, "mcp_risk_categories": [{"id": "mcp-01"}]},
        upstream,
    )

    assert result.ready is False
    assert "digest" in result.reason


def test_live_counts_are_bound_by_upstream_tree_attestation(tmp_path, monkeypatch):
    _, upstream = _signed_fixture(tmp_path, monkeypatch)

    result = verify_dataset_provenance(
        {"cve_count": 2, "mcp_risk_categories": [{"id": "mcp-01"}]},
        upstream,
    )

    assert result.ready is True


def test_missing_authenticated_upstream_provenance_fails_closed(tmp_path, monkeypatch):
    _signed_fixture(tmp_path, monkeypatch)

    result = verify_dataset_provenance(
        {"cve_count": 1, "mcp_risk_categories": [{"id": "mcp-01"}]},
        None,
    )

    assert result.ready is False
    assert result.reason == "authenticated AIG dataset provenance is unavailable"
