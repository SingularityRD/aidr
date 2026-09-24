# =============================================================================
# AIG Bridge Service — Python/FastAPI sidecar for AIDR ↔ AIG integration
# =============================================================================
# Provides a clean REST API for AIDR's core to call, translating requests into
# AIG's internal async task workflow.
#
# Attribution: This integration uses AI-Infra-Guard (Tencent Zhuque Lab)
# under Apache 2.0 license. See vendor/ai-infra-guard/NOTICE.
# =============================================================================

FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

# ── System dependencies ──────────────────────────────────────────────────────
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tzdata; \
    rm -rf /var/lib/apt/lists/*

# ── Application ──────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements-runtime.lock .
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-runtime.lock

COPY app/ ./app/

RUN useradd --system --uid 1000 --user-group --create-home bridge && \
    mkdir -p /app/uploads /app/state && \
    chown -R bridge:bridge /app

# ── Runtime configuration ────────────────────────────────────────────────────
ENV BRIDGE_HOST="0.0.0.0" \
    BRIDGE_PORT=8099 \
    BRIDGE_LOG_LEVEL=INFO \
    BRIDGE_AIG_URL="http://aig-server:8088" \
    BRIDGE_VALIDATE_DNS="true" \
    BRIDGE_RUNTIME_EGRESS_REQUIRED="true" \
    BRIDGE_DOCS_ENABLED="false" \
    BRIDGE_MAX_BODY_BYTES="52428800" \
    BRIDGE_SOURCE_ROOT="/app/uploads" \
    PYTHONUNBUFFERED=1

EXPOSE 8099

USER bridge

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8099/api/v1/readyz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099", "--log-level", "info"]
