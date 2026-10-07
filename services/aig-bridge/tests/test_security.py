"""Focused security-contract tests for the AIG bridge boundary."""

import pytest
from fastapi import HTTPException

from app.task_registry import TaskRegistry
from app.validation import (
    assert_source_path_safe,
    mcp_url_transport,
    runtime_egress_ready,
    validate_agent_config_targets,
    validate_forward_headers,
    validate_remote_url,
    validate_source_path,
)


def raises_http(callable_obj, *args, **kwargs) -> HTTPException:
    with pytest.raises(HTTPException) as caught:
        callable_obj(*args, **kwargs)
    return caught.value


def test_remote_url_rejects_literal_private_and_metadata(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    assert raises_http(validate_remote_url, "http://127.0.0.1:8080", field="target").status_code == 422
    assert raises_http(validate_remote_url, "http://169.254.169.254/latest", field="target").status_code == 422
    assert raises_http(
        validate_remote_url,
        "http://[::ffff:100.100.100.200]/latest",
        field="target",
    ).status_code == 422
    assert raises_http(
        validate_remote_url,
        "http://[::ffff:127.0.0.1]:8080",
        field="target",
    ).status_code == 422
    assert raises_http(validate_remote_url, "http://10.0.0.2:8080", field="target").status_code == 422


def test_private_target_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_ALLOW_PRIVATE_TARGETS", "true")
    assert validate_remote_url("http://10.0.0.2:8080", field="target") == "http://10.0.0.2:8080"


def test_remote_url_allows_public_ipv4_mapped_address(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.delenv("BRIDGE_ALLOW_PRIVATE_TARGETS", raising=False)
    value = "http://[::ffff:8.8.8.8]"
    assert validate_remote_url(value, field="target") == value


def test_source_path_is_rooted_and_traversal_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("BRIDGE_SOURCE_ROOT", str(tmp_path))
    upload_id = "a" * 64
    tenant_root = tmp_path / "tenant-a"
    tenant_root.mkdir()
    (tenant_root / upload_id).write_bytes(b"source")

    assert validate_source_path(upload_id, tenant_id="tenant-a") == f"tenant-a/{upload_id}"
    assert assert_source_path_safe(upload_id, tenant_id="tenant-a") == f"tenant-a/{upload_id}"
    assert raises_http(validate_source_path, "../secrets.txt", tenant_id="tenant-a").status_code == 422
    assert raises_http(validate_source_path, str(tenant_root / upload_id), tenant_id="tenant-a").status_code == 422
    assert raises_http(assert_source_path_safe, upload_id, tenant_id="tenant-b").status_code == 422


def test_forwarded_headers_reject_hop_by_hop_and_control_values():
    assert validate_forward_headers({"Authorization": "Bearer secret"}) == {
        "Authorization": "Bearer secret"
    }
    assert raises_http(validate_forward_headers, {"Host": "evil"}).status_code == 422
    assert raises_http(validate_forward_headers, {"X-Test": "ok\r\nX-Evil: yes"}).status_code == 422


def test_nested_agent_config_urls_are_validated(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    assert raises_http(
        validate_agent_config_targets,
        {"provider": {"base_url": "http://127.0.0.1:8080"}},
    ).status_code == 422
    assert raises_http(
        validate_agent_config_targets,
        {"provider": {"config": {"apiBaseUrl": "http://169.254.169.254/latest"}}},
    ).status_code == 422
    assert raises_http(
        validate_agent_config_targets,
        {"provider": {"redirectTarget": "https://example.com"}},
    ).status_code == 422
    validate_agent_config_targets(
        {"provider": {"config": {"apiBaseUrl": "https://example.com/v1"}}}
    )


_METADATA_VARIANTS = [
    "169.254.169.254",
    "169.254.169.254:80",
    "169.254.169.254/latest/meta-data",
    "//169.254.169.254/latest",
    "user@169.254.169.254:80",
    "[::ffff:169.254.169.254]:80",
    "[::ffff:169.254.169.254]",
    "::ffff:169.254.169.254",
    "[::ffff:a9fe:a9fe]:80",
    "2852039166",
    "2852039166:80",
    "0xa9fea9fe",
    "0xA9FEA9FE:8080",
    "0251.0376.0251.0376",
    "0xa9.0xfe.0xa9.0xfe",
    "169.254.43518",
    "169.16689662",
    "0251.0376.43518",
    "127.1",
    "0:8080",
    "localhost:8080",
    "metadata.google.internal",
    "fetch from 169.254.169.254:80 please",
]


@pytest.mark.parametrize("variant", _METADATA_VARIANTS)
@pytest.mark.parametrize(
    "shape",
    [
        lambda v: {"note": v},
        lambda v: {"targets": [v]},
        lambda v: {"providers": [{"name": "x", "extra": [["ok", v]]}]},
        lambda v: {"a": {"b": [{"c": {"d": [v]}}]}},
        lambda v: {v: "value-under-hostile-key"},
    ],
    ids=["value", "list", "list-of-dicts", "deep", "key"],
)
def test_agent_config_rejects_metadata_variants_at_any_depth(monkeypatch, variant, shape):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    monkeypatch.delenv("BRIDGE_ALLOW_PRIVATE_TARGETS", raising=False)
    assert raises_http(validate_agent_config_targets, shape(variant)).status_code == 422


@pytest.mark.parametrize(
    "config",
    [
        {"host": "169.254.169.254"},
        {"server": {"Host": "2852039166"}},
        {"hosts": [{"address": "0xa9fea9fe:80"}]},
        {"proxy": {"host": 2852039166}},
        {"host": "0"},
        {"host": "10.2.3"},
        {"ip": "[fd00:ec2::254]"},
        {"host": "localhost"},
        {"host": "http://169.254.169.254/"},
        {"provider": [{"base_url": "http://169.254.169.254/latest"}]},
        {"provider": [["https://example.com/nested-url-in-unknown-field"]]},
        {"provider": [{"url": ["https://example.com"]}]},
    ],
)
def test_agent_config_host_and_url_fields_inside_lists_are_validated(monkeypatch, config):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    monkeypatch.delenv("BRIDGE_ALLOW_PRIVATE_TARGETS", raising=False)
    assert raises_http(validate_agent_config_targets, config).status_code == 422


def test_agent_config_private_literals_follow_private_target_opt_in(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    monkeypatch.delenv("BRIDGE_ALLOW_PRIVATE_TARGETS", raising=False)
    assert raises_http(validate_agent_config_targets, {"nodes": ["10.0.0.5:8080"]}).status_code == 422
    monkeypatch.setenv("BRIDGE_ALLOW_PRIVATE_TARGETS", "true")
    validate_agent_config_targets({"nodes": ["10.0.0.5:8080"]})
    # Metadata and link-local stay blocked even with the opt-in.
    assert raises_http(validate_agent_config_targets, {"nodes": ["0xa9fea9fe"]}).status_code == 422


def test_agent_config_allows_legitimate_public_targets_and_ordinary_data(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    monkeypatch.delenv("BRIDGE_ALLOW_PRIVATE_TARGETS", raising=False)
    validate_agent_config_targets(
        {
            "provider": "custom",
            "model": "gpt-4o-mini",
            "temperature": "0.5",
            "max_tokens": 1024,
            "retries": "1",
            "version": "10.2.3",
            "schedule": "10:30",
            "enabled": True,
            "ratio": 0.25,
            "nothing": None,
            "endpoints": [{"url": "https://api.example.com/v1"}, {"base_url": "https://8.8.8.8/v1"}],
            "hosts": [{"host": "8.8.8.8:443"}, {"host": "[2001:4860:4860::8888]:443"}],
            "tags": ["prod", "eu-west-1", "agent:primary"],
            "contact": "ops@example.com",
            "public": ["8.8.8.8", "1.1.1.1:53", "134744072"],
            "prompt": "Summarise the ticket and reply in 2 sentences.",
            "headers": [{"name": "X-Trace", "value": "abc-123"}],
        }
    )


def test_agent_config_walk_is_bounded_and_fails_closed(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    deep: dict = {}
    cursor = deep
    for _ in range(64):
        cursor["n"] = {}
        cursor = cursor["n"]
    assert raises_http(validate_agent_config_targets, deep).status_code == 422
    assert raises_http(validate_agent_config_targets, {"items": list(range(25_000))}).status_code == 422
    assert raises_http(validate_agent_config_targets, {"blob": b"169.254.169.254"}).status_code == 422
    assert raises_http(validate_agent_config_targets, {1: "non-string key"}).status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "http://2852039166/latest",
        "http://0xa9fea9fe/latest",
        "http://0251.0376.0251.0376/",
        "http://169.254.43518/",
        "http://127.1:8080/",
    ],
)
def test_remote_url_rejects_legacy_ipv4_notation_without_dns(monkeypatch, url):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    assert raises_http(validate_remote_url, url, field="target").status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/github.com/owner/repo",
        "https://github.com.evil.example/owner/repo",
        "https://github.com@evil.example/owner/repo",
        "https://user@github.com/owner/repo",
        "https://evil.example/mcp?next=github.com",
        "https://evil.example/mcp?repo=https%3A//github.com/x/y",
        "https://www.github.com/owner/repo",
        "https://GitHub.com/owner/repo",
        "https://github.com:443/owner/repo",
        "http://github.com/owner/repo",
        "https://github.com/owner",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo?x=1",
        "https://github.com/-owner/repo",
        "https://github.com/owner/repo https://evil.example/",
        "https://evil.example/ https://github.com/owner/repo",
        "https://notgithub.com/owner/repo",
    ],
)
def test_mcp_transport_rejects_github_substring_on_other_hosts(url):
    assert raises_http(mcp_url_transport, url).status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://github.com/owner-1/my_repo.name/",
    ],
)
def test_mcp_transport_uses_git_only_for_exact_github_repository(url):
    assert mcp_url_transport(url) == "git"
    # Must agree with the vendored worker's case-sensitive substring check.
    assert "github.com" in url


@pytest.mark.parametrize(
    "url",
    ["https://mcp.example.com/sse", "https://example.com/mcp?transport=streamable", "https://gitlab.com/o/r"],
)
def test_mcp_transport_uses_live_url_mode_without_github(url):
    assert mcp_url_transport(url) == "url"
    assert "github.com" not in url


def test_runtime_egress_is_required_by_default(monkeypatch):
    monkeypatch.delenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", raising=False)
    monkeypatch.delenv("BRIDGE_EGRESS_PROXY_URL", raising=False)
    assert runtime_egress_ready() == (False, "runtime egress proxy is not configured")

    monkeypatch.setenv("BRIDGE_EGRESS_PROXY_URL", "http://egress-proxy.internal:8080")
    assert runtime_egress_ready() == (True, "runtime egress proxy configured")

    monkeypatch.setenv("BRIDGE_EGRESS_PROXY_URL", "socks5://egress-proxy.internal:1080")
    assert runtime_egress_ready() == (False, "runtime egress proxy URL is invalid")


def test_idempotency_key_cannot_change_payload():
    registry = TaskRegistry()
    registry.register("task-1", "tenant-a", "retry-1", "hash-a")
    assert registry.existing_for_key("tenant-a", "retry-1", "hash-a") == "task-1"
    with pytest.raises(ValueError):
        registry.existing_for_key("tenant-a", "retry-1", "hash-b")
    assert registry.existing_for_key("tenant-b", "retry-1", "hash-b") is None


def test_persistent_registry_survives_new_instance(tmp_path):
    db_path = str(tmp_path / "tasks.db")
    first = TaskRegistry(db_path=db_path)
    first.register("task-1", "tenant-a", "retry-1", "hash-a")

    restarted = TaskRegistry(db_path=db_path)
    assert restarted.existing_for_key("tenant-a", "retry-1", "hash-a") == "task-1"
    restarted.assert_owner("task-1", "tenant-a")
    with pytest.raises(KeyError):
        restarted.assert_owner("task-1", "tenant-b")


@pytest.mark.parametrize("url", ["http://[invalid", "http://[not-ipv6]/", "http://example.com:70000"])
def test_malformed_remote_urls_are_validation_errors(url):
    assert raises_http(validate_remote_url, url, field="target").status_code == 422


def test_malformed_runtime_proxy_fails_readiness(monkeypatch):
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_EGRESS_PROXY_URL", "http://[invalid")
    assert runtime_egress_ready() == (False, "runtime egress proxy URL is invalid")
