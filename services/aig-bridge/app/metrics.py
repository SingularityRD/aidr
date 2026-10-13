"""Bearer-protected Prometheus metrics for the AIG bridge.

``GET /metrics`` is disabled (``404``) unless ``BRIDGE_METRICS_TOKEN`` is set,
and then requires ``Authorization: Bearer <token>`` (``401`` otherwise), the
same contract as the dashboard's ``/metrics``.  The token is a monitoring-only
credential: it grants no scan, health-detail or tenant access.

Every label value comes from a fixed set (HTTP method, the matched route
*template*, status code, a fixed reason/outcome/state word), so the output
carries no task ids, tenant ids, URLs, targets, exception text or secrets.

Series:

* ``aig_bridge_http_requests_total{method,route,status}`` and
  ``aig_bridge_http_request_duration_seconds{method,route}`` -- every request
  except the probe and metrics endpoints.
* ``aig_bridge_auth_rejections_total{status}`` -- ``401``/``403`` responses.
* ``aig_bridge_upstream_failures_total{outcome}`` -- AIG calls that were
  ``rejected``, ``unavailable`` or ended with an ``ambiguous`` outcome.
* ``aig_bridge_active_tasks{state}`` -- reserved/queued/running tasks in the
  task registry, read at scrape time; ``aig_bridge_task_registry_up`` is ``0``
  when that read fails (the gauge is then absent, never reported as ``0``).
"""

from __future__ import annotations

import hmac
import logging
import os
import time
from typing import Any, Callable, Iterable, Optional

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, generate_latest
from prometheus_client.core import GaugeMetricFamily
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("aig-bridge.metrics")

METRICS_PATH = "/metrics"
# Probe and scrape traffic would drown the request series and is not user load.
UNOBSERVED_PATHS = frozenset({METRICS_PATH, "/api/v1/livez", "/api/v1/readyz"})
UPSTREAM_OUTCOMES = ("rejected", "unavailable", "ambiguous")
TASK_STATES = ("reserved", "queued", "running")
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

registry = CollectorRegistry(auto_describe=True)
http_requests = Counter(
    "aig_bridge_http_requests",
    "Bridge HTTP requests by method, matched route template and status code.",
    ("method", "route", "status"),
    registry=registry,
)
http_duration = Histogram(
    "aig_bridge_http_request_duration_seconds",
    "Bridge HTTP request duration by method and matched route template.",
    ("method", "route"),
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    registry=registry,
)
auth_rejections = Counter(
    "aig_bridge_auth_rejections",
    "Requests rejected with 401 or 403.",
    ("status",),
    registry=registry,
)
upstream_failures = Counter(
    "aig_bridge_upstream_failures",
    "AIG upstream calls that failed, by outcome.",
    ("outcome",),
    registry=registry,
)
for _outcome in UPSTREAM_OUTCOMES:
    upstream_failures.labels(outcome=_outcome)
for _status in ("401", "403"):
    auth_rejections.labels(status=_status)


def record_upstream_failure(outcome: str) -> None:
    """Count one failed AIG upstream call; unknown outcomes are refused."""

    if outcome not in UPSTREAM_OUTCOMES:
        raise ValueError(f"unknown upstream outcome: {outcome}")
    upstream_failures.labels(outcome=outcome).inc()


class _TaskRegistryCollector:
    """Read active-task depth from the task registry at scrape time."""

    def __init__(self) -> None:
        self.provider: Optional[Callable[[], Any]] = None

    def collect(self) -> Iterable[GaugeMetricFamily]:
        up = GaugeMetricFamily("aig_bridge_task_registry_up", "1 when the task registry depth read succeeded.")
        if self.provider is None:
            up.add_metric([], 0)
            yield up
            return
        try:
            counts = self.provider().active_counts_by_status()
        except Exception:
            # Never report an unreadable registry as an empty queue.
            logger.warning("task registry depth read failed during metrics scrape")
            up.add_metric([], 0)
            yield up
            return
        up.add_metric([], 1)
        yield up
        depth = GaugeMetricFamily(
            "aig_bridge_active_tasks",
            "Tasks in the registry that are reserved, queued or running.",
            labels=("state",),
        )
        for state in TASK_STATES:
            depth.add_metric([state], int(counts.get(state, 0)))
        yield depth

    def describe(self) -> Iterable[GaugeMetricFamily]:
        return []


task_registry_collector = _TaskRegistryCollector()
registry.register(task_registry_collector)


def _route_label(scope: Scope, prefix: str) -> str:
    route = scope.get("route")
    template = getattr(route, "path", None)
    if not isinstance(template, str) or not template:
        return "unmatched"
    # Some FastAPI releases record the route as declared on its APIRouter,
    # without the include_router prefix; label it with the full path either way.
    if prefix and not template.startswith(prefix) and str(scope.get("path", "")).startswith(prefix + "/"):
        return prefix + template
    return template


class MetricsMiddleware:
    """Count requests by route template; never records raw paths."""

    def __init__(self, app: ASGIApp, router_prefix: str = "") -> None:
        self.app = app
        self.router_prefix = router_prefix.rstrip("/")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("path") in UNOBSERVED_PATHS:
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status_code = 500

        async def observed_send(message: Message) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        finally:
            method = scope.get("method", "GET")
            method = method if method in _METHODS else "OTHER"
            route = _route_label(scope, self.router_prefix)
            http_requests.labels(method=method, route=route, status=str(status_code)).inc()
            http_duration.labels(method=method, route=route).observe(time.perf_counter() - started)
            if status_code in (401, 403):
                auth_rejections.labels(status=str(status_code)).inc()


def _configured_token() -> Optional[str]:
    token = os.getenv("BRIDGE_METRICS_TOKEN", "").strip()
    if not token:
        return None
    api_key = os.getenv("BRIDGE_API_KEY", "").strip()
    if api_key and hmac.compare_digest(token.encode(), api_key.encode()):
        # A scrape credential that also opens the scan API defeats its purpose.
        logger.error("BRIDGE_METRICS_TOKEN must differ from BRIDGE_API_KEY; /metrics stays disabled")
        return None
    return token


def _authorized(request: Request, token: str) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not supplied.strip():
        return False
    return hmac.compare_digest(supplied.strip().encode(), token.encode())


async def metrics_endpoint(request: Request) -> Response:
    token = _configured_token()
    if token is None:
        return Response(status_code=404, headers={"Cache-Control": "no-store"})
    if not _authorized(request, token):
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="metrics"', "Cache-Control": "no-store"},
        )
    body = b"" if request.method == "HEAD" else generate_latest(registry)
    return Response(content=body, media_type=CONTENT_TYPE_LATEST, headers={"Cache-Control": "no-store"})
