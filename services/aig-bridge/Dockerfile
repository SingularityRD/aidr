# =============================================================================
# AIG Bridge Service — Python/FastAPI sidecar for AIDR ↔ AIG integration
# =============================================================================
# Provides a clean REST API for AIDR's core to call, translating requests into
# AIG's internal async task workflow.
#
# Attribution: This integration uses AI-Infra-Guard (Tencent Zhuque Lab)
# under Apache 2.0 license. See vendor/ai-infra-guard/NOTICE.
# =============================================================================

FROM python:3.12.15-slim-trixie@sha256:ddb0207ae1f0356c2b724d740769b0c5f5f51cc54a0525178f721825f78fe74c

# ── System dependencies ──────────────────────────────────────────────────────
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libpcre2-8-0 \
        libpq5 \
        libssl3t64 \
        openssl \
        tzdata; \
    apt-get purge -y mount; \
    # DSA-6531 backports the September 2026 OpenSSL fixes to this trixie version.
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libssl3t64)" ge '3.5.7-1~deb13u3'; \
    # DSA-6530 fixes CVE-2026-103111 in the installed PCRE2 library.
    dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libpcre2-8-0)" ge '10.46-1~deb13u3'; \
    rm -rf /var/lib/apt/lists/*

# ── Application ──────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements-runtime.lock .
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-runtime.lock && \
    python -m pip check && \
    python -m pip uninstall --yes pip && \
    python -c "import shutil, sysconfig; shutil.rmtree(sysconfig.get_path('stdlib') + '/ensurepip')"

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
    PSYCOPG_IMPL="python" \
    PYTHONUNBUFFERED=1

EXPOSE 8099

USER bridge

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; urllib.request.build_opener(urllib.request.ProxyHandler({})).open(sys.argv[1], timeout=3).close()", "http://localhost:8099/api/v1/readyz"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099", "--log-level", "info"]
