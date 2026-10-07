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
_MAX_FORWARD_HEADERS = 64
_MAX_FORWARD_HEADER_VALUE = 4_096
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UPLOAD_ID_RE = re.compile(r"^[0-9a-fA-F]{64}$")

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

    required = os.getenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "true").strip().lower() in {
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
    try:
        parsed = urlparse(proxy)
        invalid = parsed.scheme not in {"http", "https"} or not parsed.hostname
        parsed.port
    except ValueError:
        invalid = True
    if invalid:
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

    # IPv4-mapped IPv6 addresses inherit the destination's IPv4 routing. Check
    # the embedded address too; otherwise cloud metadata such as
    # ::ffff:100.100.100.200 bypasses the literal IPv4 blocklist.
    effective_address = address
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        effective_address = address.ipv4_mapped
    is_metadata = str(effective_address) in {
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
    }
    # Reserved and multicast ranges are not valid customer service targets and
    # can be abused to reach provider/host control planes in unusual networks.
    blocked = (
        effective_address.is_loopback
        or effective_address.is_link_local
        or effective_address.is_unspecified
        or effective_address.is_reserved
        or effective_address.is_multicast
        or is_metadata
    )
    if blocked or (effective_address.is_private and not _allow_private_targets()):
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
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is not a valid URL",
        ) from exc
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
    # Includes inet_aton forms (``http://2852039166/``, ``http://0xa9fea9fe/``)
    # that the resolver would otherwise turn into 169.254.169.254 without a
    # DNS lookup, so they must not depend on BRIDGE_VALIDATE_DNS.
    address = parse_ip_literal(host)
    if address is not None:
        _reject_address(address, field=field)
    elif _dns_validation_enabled():
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
        "runtime_proxy_required": os.getenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "true").strip().lower() in {"1", "true", "yes", "on"},
    }


_GITHUB_HOST = "github.com"
_GITHUB_REPO_URL_RE = re.compile(
    r"^https://github\.com/"
    r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/"
    r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}?(?:\.git)?/?$"
)


def mcp_url_transport(value: str, *, field: str = "target") -> str:
    """Decide how AIG will treat a validated MCP URL target.

    The vendored AIG worker (``common/agent/mcp_task.go``) switches from a
    live MCP connection to ``git clone <prompt>`` whenever the prompt text
    contains the substring ``github.com`` (case-sensitive ``strings.Contains``).
    The bridge therefore decides the mode from the parsed URL and refuses any
    target where the substring check and the parsed host could disagree:

    * no ``github.com`` anywhere (case-insensitive) -> ``"url"``; the vendor's
      case-sensitive check is then also false;
    * the network location is exactly ``github.com`` (lowercase, no userinfo,
      no port) and the URL is ``https://github.com/<owner>/<repo>[.git][/]``
      -> ``"git"``; the vendor's check is then true and it clones exactly
      that repository;
    * anything else mentioning ``github.com`` (``evil.example/github.com``,
      ``github.com.evil.example``, ``github.com@evil.example``, query strings,
      ``www.github.com``, upper-case host, extra path segments) -> 422.

    ``www.github.com`` is rejected rather than normalised: the clone URL is
    the raw prompt, so normalising here would make the bridge's decision and
    the worker's input diverge.  Whitespace is rejected because the worker
    extracts only the first ``https?://\\S+`` match from the prompt.
    """

    if any(char.isspace() for char in value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must not contain whitespace",
        )
    if _GITHUB_HOST not in value.lower():
        return "url"
    parsed = urlparse(value)
    if parsed.netloc != _GITHUB_HOST:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"{field} mentions github.com but its host is not exactly github.com; "
                "GitHub repositories must be given as https://github.com/<owner>/<repo>"
            ),
        )
    if _GITHUB_REPO_URL_RE.fullmatch(value) is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} GitHub repositories must be given as https://github.com/<owner>/<repo>",
        )
    return "git"


def validate_source_path(value: str, *, tenant_id: str, field: str = "target") -> str:
    """Validate an opaque upload ID and return its tenant-relative reference.

    Callers never choose a filesystem path. The upload endpoint returns a
    SHA-256 upload ID, which is resolved beneath
    ``BRIDGE_SOURCE_ROOT/<tenant_id>``. Existence is checked immediately before
    dispatch by :func:`assert_source_path_safe`.
    """

    candidate_value = value.strip()
    if not _UPLOAD_ID_RE.fullmatch(candidate_value):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must be a SHA-256 upload ID",
        )
    if not _TENANT_RE.fullmatch(tenant_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid tenant identifier")

    root = Path(os.getenv("BRIDGE_SOURCE_ROOT", "/app/uploads"))
    if not root.is_absolute():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="source scanning is not configured with an absolute root",
        )
    try:
        root = root.resolve(strict=False)
        tenant_path = root / tenant_id
        if tenant_path.is_symlink():
            raise ValueError("tenant upload root may not be a symlink")
        tenant_root = tenant_path.resolve(strict=False)
        tenant_root.relative_to(root)
        relative = Path(tenant_id) / candidate_value.lower()
        candidate = root / relative
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is not a resolvable source path",
        ) from exc
    try:
        resolved.relative_to(tenant_root)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} must stay within the authenticated tenant upload root",
        ) from exc
    # Never put container filesystem paths in task payloads or API responses.
    # The worker resolves this reference beneath its own AIG_UPLOAD_ROOT.
    return relative.as_posix()


def assert_source_path_safe(value: str, *, tenant_id: str, field: str = "target") -> str:
    """Resolve and re-check a tenant upload immediately before dispatch."""

    root = Path(os.getenv("BRIDGE_SOURCE_ROOT", "/app/uploads")).resolve(strict=False)
    relative = Path(validate_source_path(value, tenant_id=tenant_id, field=field))
    resolved = root / relative
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
    try:
        real = resolved.resolve(strict=True)
        tenant_path = root / tenant_id
        if tenant_path.is_symlink():
            raise ValueError("tenant upload root may not be a symlink")
        tenant_root = tenant_path.resolve(strict=True)
        real.relative_to(tenant_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field} is missing or escapes the configured source root",
        ) from exc
    if real.is_symlink() or not real.is_file():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"{field} must be a regular file")
    return relative.as_posix()


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


_AGENT_CONFIG_MAX_DEPTH = 32
_AGENT_CONFIG_MAX_NODES = 20_000
_AGENT_CONFIG_URL_KEYS = {"url", "baseurl", "apibaseurl", "apiurl", "serverurl", "webhookurl"}
# Keys whose value is, by convention, a bare host / host:port.  Their values
# are validated as hosts in full (any IPv4 notation, blocked names and, when
# enabled, DNS resolution).  Other string values are scanned only for tokens
# that are unambiguously host literals, to avoid rejecting ordinary data.
_AGENT_CONFIG_HOST_KEYS = {
    "host",
    "hostname",
    "hostport",
    "ip",
    "ipaddress",
    "address",
    "addr",
    "serverhost",
    "serveraddress",
    "proxy",
    "proxyhost",
}
_INET_ATON_PART_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)$")
_TOKEN_TRIM = "\"'`()<>{},;"


def _inet_aton_parts(text: str) -> list[str] | None:
    """Split ``text`` into legacy IPv4 components, or return ``None``."""

    candidate = text[:-1] if text.endswith(".") else text
    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4 or not all(_INET_ATON_PART_RE.fullmatch(part) for part in parts):
        return None
    return parts


def _legacy_ipv4(text: str) -> ipaddress.IPv4Address | None:
    """Parse the IPv4 notations accepted by ``inet_aton``/libc resolvers.

    ``ipaddress`` only accepts canonical dotted-quad decimal, but the C
    resolver used by curl, Python sockets and most HTTP clients also accepts
    ``2852039166``, ``0xa9fea9fe``, ``0251.0376.0251.0376`` and
    ``169.254.43518``.  All of them reach 169.254.169.254, so the bridge must
    normalise them before applying the address policy.
    """

    parts = _inet_aton_parts(text)
    if parts is None:
        return None
    values = []
    for part in parts:
        if part[:2].lower() == "0x":
            values.append(int(part[2:], 16))
        elif len(part) > 1 and part.startswith("0"):
            values.append(int(part, 8))
        else:
            values.append(int(part))
    *head, last = values
    if any(value > 0xFF for value in head) or last >= 256 ** (4 - len(head)):
        return None
    number = 0
    for value in head:
        number = (number << 8) | value
    number = (number << (8 * (4 - len(head)))) | last
    return ipaddress.IPv4Address(number)


def parse_ip_literal(host: str) -> ipaddress._BaseAddress | None:
    """Return the address a host literal reaches, including legacy IPv4 forms."""

    candidate = host.strip().lower().rstrip(".")
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    # Strip an IPv6 zone identifier ("fe80::1%eth0"); the scope does not
    # change which address is reached.
    candidate = candidate.split("%", 1)[0]
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return _legacy_ipv4(candidate)


def _config_error(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail)


def _split_host_port(token: str) -> tuple[str, int | None] | None:
    """Split ``host``, ``host:port``, ``[v6]``, ``[v6]:port`` or a bare IPv6.

    Also drops a ``user@`` prefix and anything after the first ``/`` so
    ``169.254.169.254/latest`` and ``//metadata/`` are recognised.  Returns
    ``None`` when the token cannot be a host reference.
    """

    value = token.lstrip("/")
    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.rsplit("@", 1)[-1]
    if not value:
        return None
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        host, rest = value[: end + 1], value[end + 1 :]
        if not rest:
            return host, None
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return None
    if value.count(":") > 1:
        # Unbracketed IPv6 literal (e.g. ``::ffff:169.254.169.254``).
        return value, None
    host, sep, port = value.partition(":")
    if not sep:
        return host, None
    if port.isdigit():
        return host, int(port)
    return None


def _check_config_host(value: str, *, field: str) -> None:
    """Strictly validate a value stored under a host-style key."""

    split = _split_host_port(value.strip())
    if split is None:
        raise _config_error(f"{field} must be a host or host:port")
    host, port = split
    if port is not None and not 1 <= port <= 65_535:
        raise _config_error(f"{field} has an invalid port")
    normalized = host.strip("[]").lower().rstrip(".")
    if not normalized:
        raise _config_error(f"{field} must be a host or host:port")
    if normalized in _BLOCKED_HOSTNAMES:
        raise _config_error(f"{field} points to a blocked host")
    address = parse_ip_literal(host)
    if address is not None:
        _reject_address(address, field=field)
    elif _dns_validation_enabled():
        _validate_resolved_addresses(normalized, port or 443, field=field)


def _check_config_token(token: str, *, field: str) -> None:
    """Reject a free-form token that is unambiguously a blocked host literal.

    Only notations that a resolver would actually treat as an address are
    considered, so ordinary values such as ``"0.5"`` or ``"1"`` pass.
    """

    split = _split_host_port(token)
    if split is None:
        return
    host, port = split
    if port is not None and not 0 <= port <= 65_535:
        return
    normalized = host.strip("[]").lower().rstrip(".")
    if not normalized:
        return
    if normalized in _BLOCKED_HOSTNAMES:
        raise _config_error(f"{field} points to a blocked host")
    if host.startswith("[") or ":" in normalized:
        address = parse_ip_literal(host)
        if address is not None:
            _reject_address(address, field=field)
        return
    parts = _inet_aton_parts(normalized)
    if parts is None:
        return
    address = _legacy_ipv4(normalized)
    if address is None:
        return
    plain_decimal = all(part == "0" or part[0] in "123456789" for part in parts)
    if len(parts) == 1:
        # A bare decimal number is only an address when it is too large to be
        # an ordinary count (``2852039166``) or is ``0:<port>``.  Hex/octal
        # notation is always treated as an address.  Reserved/multicast
        # results cannot be reached over TCP, so ordinary large numeric
        # identifiers in that range are not rejected.
        if plain_decimal and int(address) < 1 << 24 and not (normalized == "0" and port is not None):
            return
        if address.is_reserved or address.is_multicast:
            return
    elif len(parts) < 4 and port is None and plain_decimal and int(parts[-1]) <= 0xFF:
        # ``"0.5"`` or ``"10.2.3"`` are far more likely numbers/versions than
        # hosts; only the loopback/link-local short forms (``127.1``,
        # ``169.254.1``) are rejected.  ``169.254.43518`` (last part > 255),
        # octal/hex parts or an explicit port always count as an address.
        if not (address.is_loopback or address.is_link_local):
            return
    _reject_address(address, field=field)


def _dns_validation_enabled() -> bool:
    return os.getenv("BRIDGE_VALIDATE_DNS", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _check_config_string(value: str, *, field: str) -> None:
    if "://" in value:
        raise _config_error(f"unsupported URL field: {field}")
    for raw in value.split():
        token = raw.strip(_TOKEN_TRIM).rstrip(".")
        if token:
            _check_config_token(token, field=field)


def validate_agent_config_targets(config: dict) -> None:
    """Validate every string in an inline agent configuration.

    Agent configs are serialized to YAML and may cause AIG workers to call a
    customer-controlled endpoint.  Every string at every depth (mapping keys
    and values, list items, lists of mappings) is inspected so a config cannot
    hide an SSRF target in a nested mapping or list:

    * conventional URL keys must hold a validated http(s) URL;
    * URL values anywhere else are rejected instead of being forwarded to a
      flexible upstream schema;
    * host-style keys must hold a validated host or host:port;
    * any other string is scanned for host literals (``host:port``, bracketed
      or IPv4-mapped IPv6, decimal/hex/octal/short IPv4 forms) and blocked
      private/metadata destinations are rejected.

    The walk is bounded in depth and node count and fails closed (422) when
    either bound is exceeded or an unsupported value type is encountered.
    """

    nodes = 0

    def field_name(path: tuple[str, ...]) -> str:
        return "agent_config" + "".join(path)

    def walk(value: object, path: tuple[str, ...], depth: int, kind: str) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _AGENT_CONFIG_MAX_NODES:
            raise _config_error("agent_config has too many elements")
        if depth > _AGENT_CONFIG_MAX_DEPTH:
            raise _config_error("agent_config is nested too deeply")
        field = field_name(path)
        if isinstance(value, dict):
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise _config_error(f"{field} keys must be strings")
                key_path = (*path, f".{key}")
                key_field = field_name(key_path)
                _check_config_string(key, field=key_field)
                canonical_key = re.sub(r"[^a-z0-9]", "", key.lower())
                if canonical_key in _AGENT_CONFIG_URL_KEYS:
                    if not isinstance(nested, str):
                        raise _config_error(f"{key_field} must be an http(s) URL")
                    nodes += 1
                    target_policy(nested, field=key_field)
                    continue
                child_kind = "host" if canonical_key in _AGENT_CONFIG_HOST_KEYS else "data"
                walk(nested, key_path, depth + 1, child_kind)
        elif isinstance(value, (list, tuple)):
            for index, nested in enumerate(value):
                # List items inherit the parent's key semantics, so
                # ``{"hosts": [...]}`` style lists stay host-validated only
                # when the parent key is a host key.
                walk(nested, (*path, f"[{index}]"), depth + 1, kind)
        elif isinstance(value, str):
            if kind == "host":
                if "://" in value:
                    raise _config_error(f"unsupported URL field: {field}")
                _check_config_host(value, field=field)
            else:
                _check_config_string(value, field=field)
        elif isinstance(value, bool) or value is None or isinstance(value, float):
            return
        elif isinstance(value, int):
            # ``{"host": 2852039166}`` reaches 169.254.169.254 once a worker
            # stringifies it, so integers under host-style keys are hosts.
            if kind == "host":
                _check_config_host(str(value), field=field)
        else:
            raise _config_error(f"{field} has an unsupported value type")

    try:
        walk(config, (), 0, "data")
    except RecursionError as exc:
        raise _config_error("agent_config is nested too deeply") from exc
