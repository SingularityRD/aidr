"""Authenticated, content-addressed upload endpoint for source scans."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile, status

from app.auth import RequestContext, get_request_context
from app.models.schemas import UploadResponse
from app.uploads import store_upload, validate_archive

router = APIRouter()


@router.post("/uploads", response_model=UploadResponse, summary="Upload a tenant-scoped scan source")
async def upload_source(
    file: UploadFile = File(...),
    context: RequestContext = Depends(get_request_context),
    expected_sha256: str | None = Header(default=None, alias="X-Content-SHA256"),
):
    if os.getenv("BRIDGE_UPLOAD_ENABLED", "true").strip().lower() not in {"1", "true", "yes", "on"}:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="uploads are disabled")
    root = Path(os.getenv("BRIDGE_UPLOAD_ROOT", os.getenv("BRIDGE_SOURCE_ROOT", "/app/uploads")))
    path = None
    try:
        path, digest, size = store_upload(
            file.file,
            root=root,
            tenant_id=context.tenant_id,
            expected_sha256=expected_sha256,
        )
        archive = validate_archive(path)
    except HTTPException:
        if path is not None:
            path.unlink(missing_ok=True)
        raise
    except (OSError, ValueError) as exc:
        if path is not None:
            path.unlink(missing_ok=True)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="upload could not be validated") from exc
    return UploadResponse(
        upload_id=digest,
        sha256=digest,
        bytes=size,
        source_path=(Path(context.tenant_id) / digest).as_posix(),
        archive_kind=str(archive["kind"]),
        archive_entries=int(archive["entries"]),
    )
