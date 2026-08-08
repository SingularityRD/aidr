"""Content-addressed upload and archive safety primitives.

The current AIG upstream accepts paths in a shared volume and has no complete
archive policy.  These helpers are used by a future broker/upload endpoint and
are safe to call before handing a path to AIG.  They never extract archives as
root and reject traversal, links, special files and decompression bombs.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO, Optional

from fastapi import HTTPException, status


def _limit(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


MAX_UPLOAD_BYTES = _limit("BRIDGE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)
MAX_ARCHIVE_ENTRIES = _limit("BRIDGE_MAX_ARCHIVE_ENTRIES", 10_000)
MAX_ARCHIVE_UNCOMPRESSED = _limit("BRIDGE_MAX_ARCHIVE_UNCOMPRESSED_BYTES", 200 * 1024 * 1024)
try:
    MAX_COMPRESSION_RATIO = max(1.0, float(os.getenv("BRIDGE_MAX_COMPRESSION_RATIO", "100")))
except ValueError:
    MAX_COMPRESSION_RATIO = 100.0


def content_addressed_path(root: str | Path, tenant_id: str, digest: str) -> Path:
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
        raise ValueError("invalid SHA-256 digest")
    safe_tenant = "".join(char for char in tenant_id if char.isalnum() or char in "._:-")
    if not safe_tenant or safe_tenant != tenant_id:
        raise ValueError("invalid tenant identifier")
    return Path(root).resolve(strict=False) / safe_tenant / digest.lower()


def store_upload(
    stream: BinaryIO,
    *,
    root: str | Path,
    tenant_id: str,
    expected_sha256: Optional[str] = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> tuple[Path, str, int]:
    """Stream an upload into a tenant-scoped SHA-256 object."""

    root_path = Path(root).resolve(strict=False)
    root_path.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(prefix="upload-", dir=root_path, delete=False)
    digest = hashlib.sha256()
    size = 0
    try:
        with temporary as destination:
            while True:
                chunk = stream.read(min(1024 * 1024, max_bytes - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="upload exceeds size limit")
                digest.update(chunk)
                destination.write(chunk)
        calculated = digest.hexdigest()
        if expected_sha256 and expected_sha256.lower() != calculated:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="upload digest mismatch")
        target = content_addressed_path(root_path, tenant_id, calculated)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            Path(temporary.name).unlink(missing_ok=True)
        else:
            shutil.move(temporary.name, target)
        return target, calculated, size
    except Exception:
        Path(temporary.name).unlink(missing_ok=True)
        raise


def _safe_member(name: str) -> bool:
    path = Path(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def validate_archive(path: str | Path) -> dict[str, int | str]:
    """Validate ZIP/TAR/GZip members without extracting them."""

    source = Path(path).resolve(strict=True)
    total = 0
    entries = 0
    kind = "file"
    try:
        if zipfile.is_zipfile(source):
            kind = "zip"
            with zipfile.ZipFile(source) as archive:
                infos = archive.infolist()
                entries = len(infos)
                if entries > MAX_ARCHIVE_ENTRIES:
                    raise ValueError("archive entry limit exceeded")
                for info in infos:
                    if not _safe_member(info.filename) or info.is_dir():
                        if not _safe_member(info.filename):
                            raise ValueError("archive path traversal")
                        continue
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if mode and (stat.S_ISLNK(mode) or not stat.S_ISREG(mode)):
                        raise ValueError("archive contains unsafe member")
                    total += int(info.file_size)
                    if total > MAX_ARCHIVE_UNCOMPRESSED:
                        raise ValueError("archive expanded size limit exceeded")
                    if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                        raise ValueError("archive compression ratio limit exceeded")
        elif tarfile.is_tarfile(source):
            kind = "tar"
            with tarfile.open(source, "r:*") as archive:
                for member in archive:
                    entries += 1
                    if entries > MAX_ARCHIVE_ENTRIES:
                        raise ValueError("archive entry limit exceeded")
                    if not _safe_member(member.name) or member.issym() or member.islnk() or not member.isfile():
                        raise ValueError("archive contains unsafe member")
                    total += int(member.size)
                    if total > MAX_ARCHIVE_UNCOMPRESSED:
                        raise ValueError("archive expanded size limit exceeded")
        else:
            return {"kind": kind, "entries": 0, "uncompressed_bytes": source.stat().st_size}
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unsafe or corrupt archive") from exc
    return {"kind": kind, "entries": entries, "uncompressed_bytes": total}
