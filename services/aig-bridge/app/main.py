"""
AIG Bridge — FastAPI entry point.

Initialises the FastAPI application, registers routers, configures middleware,
and exposes the health check endpoint.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health, scan

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
