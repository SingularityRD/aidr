"""Focused security-contract tests for the AIG bridge boundary."""

import pytest
from fastapi import HTTPException

from app.task_registry import TaskRegistry
from app.validation import (
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
    assert raises_http(validate_remote_url, "http://10.0.0.2:8080", field="target").status_code == 422


def test_private_target_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_ALLOW_PRIVATE_TARGETS", "true")
    assert validate_remote_url("http://10.0.0.2:8080", field="target") == "http://10.0.0.2:8080"


def test_source_path_is_rooted_and_traversal_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("BRIDGE_SOURCE_ROOT", str(tmp_path))
    assert validate_source_path("bundle.zip") == str(tmp_path / "bundle.zip")
    assert raises_http(validate_source_path, "../secrets.txt").status_code == 422
    assert raises_http(validate_source_path, "/etc/passwd").status_code == 422


def test_forwarded_headers_reject_hop_by_hop_and_control_values():
    assert validate_forward_headers({"Authorization": "Bearer secret"}) == {
        "Authorization": "Bearer secret"
    }
    assert raises_http(validate_forward_headers, {"Host": "evil"}).status_code == 422
    assert raises_http(validate_forward_headers, {"X-Test": "ok\r\nX-Evil: yes"}).status_code == 422


def test_nested_agent_config_urls_are_validated(monkeypatch):
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    assert raises_http(
        validate_agent_config_targets,
        {"provider": {"base_url": "http://127.0.0.1:8080"}},
    ).status_code == 422


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
