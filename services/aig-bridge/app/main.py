"""
AIG Bridge — FastAPI entry point.

Initialises the FastAPI application, registers routers, configures middleware,
and exposes the health check endpoint.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info("AIG Bridge starting up — version %s", __import__("app").__version__)
    yield
    await close_aig_client()
    logger.info("AIG Bridge shutting down")


app = FastAPI(
    title="AIG Bridge — AIDR × AI-Infra-Guard Integration",
    description=(
        "REST API bridging Singularity AIDR and Tencent AI-Infra-Guard. "
        "Provides AI infrastructure CVE scanning, MCP server security analysis, "
        "Agent-Scan workflows, jailbreak evaluation, and threat intelligence sync."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

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
