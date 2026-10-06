"""Authenticated, content-addressed upload endpoint for source scans."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile, status

from app.auth import RequestContext, get_request_context
from app.models.schemas import UploadResponse
from app.uploads import store_upload

router = APIRouter()


@router.post("/uploads", response_model=UploadResponse, summary="Upload a tenant-scoped scan source")
def upload_source(
    file: UploadFile = File(...),
    context: RequestContext = Depends(get_request_context),
    expected_sha256: str | None = Header(default=None, alias="X-Content-SHA256"),
):
    if os.getenv("BRIDGE_UPLOAD_ENABLED", "true").strip().lower() not in {"1", "true", "yes", "on"}:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="uploads are disabled")
    root = Path(os.getenv("BRIDGE_UPLOAD_ROOT", os.getenv("BRIDGE_SOURCE_ROOT", "/app/uploads")))
    try:
        _path, digest, size, archive = store_upload(
            file.file,
            root=root,
            tenant_id=context.tenant_id,
            expected_sha256=expected_sha256,
            require_archive=True,
        )
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="upload storage is unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="upload could not be validated") from exc
    return UploadResponse(
        upload_id=digest,
        sha256=digest,
        bytes=size,
        source_path=(Path(context.tenant_id) / digest).as_posix(),
        archive_kind=str(archive["kind"]),
        archive_entries=int(archive["entries"]),
    )
