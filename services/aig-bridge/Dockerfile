# =============================================================================
# AIG Bridge Service — Python/FastAPI sidecar for AIDR ↔ AIG integration
# =============================================================================
# Provides a clean REST API for AIDR's core to call, translating requests into
# AIG's internal async task workflow.
#
# Attribution: This integration uses AI-Infra-Guard (Tencent Zhuque Lab)
# under Apache 2.0 license. See vendor/ai-infra-guard/NOTICE.
# =============================================================================

FROM python:3.14.8-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# ── System dependencies ──────────────────────────────────────────────────────
# CPython's library finder needs ld/objdump and libpq's linker name on musl.
RUN set -eux; \
    apk add --no-cache \
        ca-certificates \
        binutils \
        'libpq>=18.6-r0' \
        'libpq-dev>=18.6-r0' \
        'libssl3>=3.5.9-r0' \
        'libcrypto3>=3.5.9-r0' \
        'busybox>=1.37.0-r31' \
        'musl>=1.2.6-r2' \
        'sqlite-libs>=3.53.4-r0' \
        'libuuid>=2.42.3-r1' \
        'libncursesw>=6.6_p20260516-r0' \
        tzdata

# ── Application ──────────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements-runtime.lock .
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements-runtime.lock && \
    python -m pip check && \
    PSYCOPG_IMPL=python python -c "import psycopg; assert psycopg.pq.__impl__ == 'python'; assert psycopg.pq.version() >= 180006" && \
    python -m pip uninstall --yes pip && \
    python -c "import shutil, sysconfig; shutil.rmtree(sysconfig.get_path('stdlib') + '/ensurepip')"

COPY app/ ./app/

RUN addgroup -S -g 1000 bridge && \
    adduser -S -D -u 1000 -G bridge -h /home/bridge bridge && \
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
