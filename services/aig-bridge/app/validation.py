"""Input validation for externally reachable AIG scan targets."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from fastapi import HTTPException, status


_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data.ec2.internal",
    "host.docker.internal",
}

_MAX_URL_LENGTH = 2_048
_MAX_SOURCE_LENGTH = 512
_MAX_FORWARD_HEADERS = 64
_MAX_FORWARD_HEADER_VALUE = 4_096
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

# These headers either control the hop-to-hop connection or can be used to
# smuggle a caller-controlled routing identity through a proxy.  The bridge
# forwards MCP headers to AIG as data, so rejecting them here prevents AIG
# workers from accidentally treating them as transport metadata.
_BLOCKED_FORWARD_HEADERS = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
}
_SENSITIVE_QUERY_NAMES = {
    "token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "authorization",
    "signature",
    "sig",
    "access_token",
    "refresh_token",
}


def _allow_private_targets() -> bool:
    value = os.getenv("BRIDGE_ALLOW_PRIVATE_TARGETS", "false")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def runtime_egress_ready() -> tuple[bool, str]:
    """Return whether a runtime egress policy is configured.

    Submission-time DNS checks are not sufficient against rebinds and
    redirects.  Production must provide an egress proxy/gateway that repeats
    the check immediately before every hop.  The bridge can still run locally
    with this requirement disabled explicitly.
    """

    required = os.getenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not required:
        return True, "submission-time validation only"
    proxy = os.getenv("BRIDGE_EGRESS_PROXY_URL", "").strip()
    if not proxy:
        return False, "runtime egress proxy is not configured"
    parsed = urlparse(proxy)
    if parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
        return False, "runtime egress proxy URL is invalid"
    return True, "runtime egress proxy configured"


def _validate_resolved_addresses(host: str, port: int, *, field: str) -> None:
    """Resolve a hostname and reject addresses that could reach host services.

    Literal checks alone are vulnerable to DNS rebinding: a hostname can first
    resolve to a public address and later to loopback or cloud metadata.  This
    check closes the common submission-time hole.  The AIG worker must still
    apply the same policy immediately before connecting because the DNS answer
    can change after this request returns.
    """

    try:
        infos = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, socket.gaierror) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} host could not be resolved",
        ) from exc

    addresses = {str(item[4][0]) for item in infos if item[4]}
    if not addresses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} host could not be resolved",
        )
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        _reject_address(address, field=field)


def _reject_address(address: ipaddress._BaseAddress, *, field: str) -> None:
    """Reject an IP address that must never be used as a scan target."""

    is_metadata = str(address) in {
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
    }
    # Reserved and multicast ranges are not valid customer service targets and
    # can be abused to reach provider/host control planes in unusual networks.
    blocked = (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
        or address.is_multicast
        or is_metadata
    )
    if blocked or (address.is_private and not _allow_private_targets()):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} points to a blocked private or metadata address",
        )


def validate_remote_url(value: str, *, field: str) -> str:
    """Validate a remote URL and reject common SSRF destinations.

    Customer deployments that intentionally scan private RFC1918 services can
    opt in explicitly with ``BRIDGE_ALLOW_PRIVATE_TARGETS=true``.  Loopback,
    link-local and cloud metadata destinations remain blocked in all modes.
    """

    candidate = value.strip()
    if not candidate or len(candidate) > _MAX_URL_LENGTH or any(
        ord(char) < 0x20 or ord(char) == 0x7F for char in candidate
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is not a valid URL",
        )
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must be an http(s) URL",
        )
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must not contain URL credentials",
        )
    if parsed.fragment:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must not contain a URL fragment",
        )
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if name.lower() in _SENSITIVE_QUERY_NAMES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{field} must not contain credentials in the query string",
            )
    if host in _BLOCKED_HOSTNAMES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} points to a blocked host",
        )
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} has an invalid port",
        ) from exc
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        _reject_address(address, field=field)
    elif os.getenv("BRIDGE_VALIDATE_DNS", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }:
        _validate_resolved_addresses(host, port, field=field)
    return candidate


def target_policy(value: str, *, field: str = "target") -> dict[str, object]:
    """Return non-secret policy metadata for a worker-side egress gateway."""

    validated = validate_remote_url(value, field=field)
    parsed = urlparse(validated)
    ready, reason = runtime_egress_ready()
    if not ready:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=reason)
    return {
        "scheme": parsed.scheme,
        "host": (parsed.hostname or "").lower().rstrip("."),
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "runtime_proxy_required": os.getenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false").lower() in {"1", "true", "yes", "on"},
    }


def validate_source_path(value: str, *, field: str = "target") -> str:
    """Constrain source scans to the configured shared upload directory.

    Source targets are paths consumed by the AIG worker.  They are not allowed
    to select arbitrary bridge/AIG filesystem locations.  The returned path is
    rooted at ``BRIDGE_SOURCE_ROOT`` (``/app/uploads`` in the compose stack),
    and existing symlinks must remain inside that root.  Existence is not
    required here because the upload may live in a shared volume visible only
    to the worker; the worker must perform its own final existence check.
    """

    candidate_value = value.strip()
    if (
        not candidate_value
        or len(candidate_value) > _MAX_SOURCE_LENGTH
        or "\x00" in candidate_value
        or "\\" in candidate_value
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is not a valid source path",
        )

    root = Path(os.getenv("BRIDGE_SOURCE_ROOT", "/app/uploads"))
    if not root.is_absolute():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="source scanning is not configured with an absolute root",
        )
    try:
        root = root.resolve(strict=False)
        raw = Path(candidate_value)
        candidate = raw if raw.is_absolute() else root / raw
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is not a resolvable source path",
        ) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must stay within the configured source root",
        ) from exc
    return str(resolved)


def assert_source_path_safe(value: str, *, field: str = "target") -> str:
    """Re-check an existing source path immediately before worker dispatch."""

    root = Path(os.getenv("BRIDGE_SOURCE_ROOT", "/app/uploads")).resolve(strict=False)
    raw = Path(value.strip())
    candidate = raw if raw.is_absolute() else root / raw
    # Inspect the path as supplied, before resolve() erases the symlink
    # component. A symlink that happens to point back inside the root is still
    # rejected because it can be swapped between validation and worker open.
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must stay within the configured source root",
        ) from exc
    cursor = root
    for component in relative.parts:
        if cursor.is_symlink():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{field} may not traverse a symlink",
            )
        cursor = cursor / component
    if cursor.is_symlink():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"{field} may not be a symlink")
    resolved = Path(validate_source_path(value, field=field))
    try:
        real = resolved.resolve(strict=True)
        real.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is missing or escapes the configured source root",
        ) from exc
    if real.is_symlink():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"{field} may not be a symlink")
    return str(real)


def validate_forward_headers(headers: dict[str, str]) -> dict[str, str]:
    """Validate and normalize headers that AIG will use for a remote target."""

    if len(headers) > _MAX_FORWARD_HEADERS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="too many target headers",
        )
    normalized: dict[str, str] = {}
    seen_names: set[str] = set()
    for name, value in headers.items():
        header_name = str(name).strip()
        header_value = str(value)
        lower_name = header_name.lower()
        if (
            not _HEADER_NAME_RE.fullmatch(header_name)
            or lower_name in _BLOCKED_FORWARD_HEADERS
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in header_value)
            or len(header_value) > _MAX_FORWARD_HEADER_VALUE
            or lower_name in seen_names
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"invalid target header: {header_name or '<empty>'}",
            )
        seen_names.add(lower_name)
        normalized[header_name] = header_value
    return normalized


def validate_agent_config_targets(config: dict) -> None:
    """Validate URL-bearing fields in an inline agent configuration.

    Agent configs are serialized to YAML and may cause AIG workers to call a
    customer-controlled endpoint.  Validate the conventional URL keys at the
    bridge boundary so a config cannot hide an obvious SSRF target in a nested
    mapping.  Unknown keys are left untouched for AIG's own schema validation.
    """

    url_keys = {"url", "base_url", "endpoint", "api_url", "server_url", "webhook_url"}

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if str(key).lower() in url_keys and isinstance(nested, str) and "://" in nested:
                    validate_remote_url(nested, field=f"agent_config.{key}")
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(config)
