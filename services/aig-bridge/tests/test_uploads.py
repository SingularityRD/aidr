"""Source archives must be usable and safe before becoming scan targets."""

import io
import stat
import tarfile
import zipfile

import pytest
from fastapi import HTTPException

from app.uploads import store_upload, validate_archive


def test_standard_zip_permissions_are_accepted(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("src/", b"")
        bundle.writestr("src/main.py", b"print('safe')")
    assert validate_archive(archive)["entries"] == 2


def test_tar_gzip_directories_are_accepted(tmp_path):
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        directory = tarfile.TarInfo("src")
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)
        member = tarfile.TarInfo("src/main.py")
        member.size = 4
        bundle.addfile(member, io.BytesIO(b"safe"))
    assert validate_archive(archive) == {"kind": "tar.gz", "entries": 2, "uncompressed_bytes": 4}


def test_unsafe_archive_is_never_published(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        bundle.writestr("../escape.txt", b"unsafe")
    stream.seek(0)
    with pytest.raises(HTTPException):
        store_upload(stream, root=tmp_path, tenant_id="tenant-a", require_archive=True)
    assert list(tmp_path.iterdir()) == []


def test_directory_symlink_in_zip_is_rejected(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        member = zipfile.ZipInfo("src/")
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        bundle.writestr(member, b"../outside")
    with pytest.raises(HTTPException):
        validate_archive(archive)


def test_corrupt_zip_member_is_rejected(tmp_path):
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr("main.py", b"original-content")
    archive.write_bytes(archive.read_bytes().replace(b"original-content", b"modified-content"))
    with pytest.raises(HTTPException):
        validate_archive(archive)


def test_plain_files_cannot_be_source_archives(tmp_path):
    with pytest.raises(HTTPException, match="source uploads must be ZIP or tar.gz"):
        store_upload(io.BytesIO(b"plain source"), root=tmp_path, tenant_id="tenant-a", require_archive=True)
    assert list(tmp_path.iterdir()) == []
