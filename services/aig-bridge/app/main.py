"""
AIG Bridge — FastAPI entry point.

Initialises the FastAPI application, registers routers, configures middleware,
and exposes the health check endpoint.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import health, scan, uploads
from app.utils.aig_client import AIGClientError, close_aig_client

# ── Logging ─────────────────────────────────────────────────────────────────
log_level = os.getenv("BRIDGE_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("aig-bridge")


class _BodyTooLarge(Exception):
    """Raised while receiving a request that exceeds the configured limit."""


class BodySizeLimitMiddleware:
    """Reject oversized requests while ASGI is still streaming their body."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max(1, max_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        content_length = next(
            (value for name, value in scope.get("headers", []) if name.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._reject(send)

    async def _reject(self, send: Send) -> None:
        body = b'{"detail":"request body exceeds configured limit"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})


def _max_body_bytes() -> int:
    try:
        return max(1, int(os.getenv("BRIDGE_MAX_BODY_BYTES", str(50 * 1024 * 1024))))
    except ValueError:
        return 50 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info("AIG Bridge starting up — version %s", __import__("app").__version__)
    yield
    await close_aig_client()
    logger.info("AIG Bridge shutting down")


docs_enabled = os.getenv("BRIDGE_DOCS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
app = FastAPI(
    title="AIG Bridge — AIDR × AI-Infra-Guard Integration",
    description=(
        "REST API bridging Singularity AIDR and Tencent AI-Infra-Guard. "
        "Provides AI infrastructure CVE scanning, MCP server security analysis, "
        "Agent-Scan workflows, jailbreak evaluation, and threat intelligence sync."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if docs_enabled else None,
    redoc_url="/redoc" if docs_enabled else None,
    openapi_url="/openapi.json" if docs_enabled else None,
)

# Reject oversized bodies before Starlette/FastAPI parses or buffers them.  The
# upload helper has its own 50 MiB streaming limit; this outer limit also covers
# JSON, multipart framing, and chunked requests.
app.add_middleware(BodySizeLimitMiddleware, max_bytes=_max_body_bytes())

# ── CORS — allow AIDR dashboard and dev tools ──────────────────────────────
configured_origins = [
    origin.strip()
    for origin in os.getenv("BRIDGE_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if "*" in configured_origins:
    # A wildcard origin plus credentials is an accidental data-exfiltration
    # configuration.  Ignore it rather than silently exposing scan results.
    logger.error("Ignoring wildcard BRIDGE_CORS_ORIGINS; configure explicit origins")
    configured_origins = []
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins,
    allow_credentials=bool(configured_origins),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "X-API-Key",
        "X-AIDR-Tenant-ID",
    ],
)


@app.exception_handler(AIGClientError)
async def aig_error_handler(_request: Request, exc: AIGClientError):
    """Return a stable upstream error without leaking request secrets."""

    return JSONResponse(
        status_code=502,
        # AIG may echo target headers, model tokens, or task payloads in an
        # error body.  Keep the wire response deliberately generic; details
        # belong in redacted server-side telemetry only.
        content={"error": "aig_upstream_unavailable", "detail": "upstream AIG request failed"},
    )

# ── Routers ─────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(uploads.router, prefix="/api/v1", tags=["uploads"])
