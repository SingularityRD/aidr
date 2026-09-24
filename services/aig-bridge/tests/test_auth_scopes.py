"""Focused authorization checks for broker JWT scopes."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import auth
from app.auth import BrokerClaims, get_request_context


def _request(method: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/api/v1/scan/infra",
            "headers": [],
            "query_string": b"",
            "scheme": "https",
            "server": ("test", 443),
            "client": ("test", 1),
        }
    )


def _claims(*scopes: str) -> BrokerClaims:
    return BrokerClaims(
        subject="broker-worker",
        tenant_id="tenant-a",
        scopes=frozenset(scopes),
        job_id=None,
        jti="scope-test",
        expires_at=2_000_000_000,
        claims={},
    )


@pytest.mark.parametrize(
    ("method", "granted_scope", "missing_scope"),
    [("GET", "aig:read", "aig:scan"), ("POST", "aig:scan", "aig:read")],
)
def test_broker_routes_require_canonical_scope(method: str, granted_scope: str, missing_scope: str):
    context = asyncio.run(get_request_context(_request(method), _claims(granted_scope), None))
    assert granted_scope in context.scopes

    with pytest.raises(HTTPException) as denied:
        asyncio.run(get_request_context(_request(method), _claims(missing_scope), None))
    assert denied.value.status_code == 403
    assert denied.value.detail == f"{granted_scope} scope is required"


def test_local_api_key_mode_does_not_require_broker_scopes(monkeypatch):
    monkeypatch.setenv("BRIDGE_TENANT_REQUIRED", "false")
    context = asyncio.run(get_request_context(_request("POST"), None, None))
    assert context.tenant_id == "local"
    assert not context.scopes


def test_required_auth_rejects_disabled_mode(monkeypatch):
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "disabled")
    assert not auth.auth_is_configured()
    with pytest.raises(HTTPException) as disabled:
        asyncio.run(auth.require_bridge_api_key(_request("POST")))
    assert disabled.value.status_code == 503


@pytest.mark.parametrize(
    ("secret", "issuer", "audience"),
    [
        ("too-short", "https://broker.example.test", "aidr-aig-bridge"),
        ("x" * 32, "", "aidr-aig-bridge"),
        ("x" * 32, "https://broker.example.test", ""),
    ],
)
def test_required_auth_rejects_incomplete_broker_config(monkeypatch, secret, issuer, audience):
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "broker")
    monkeypatch.setenv("BRIDGE_JWT_SECRET", secret)
    monkeypatch.setenv("BRIDGE_JWT_ISSUER", issuer)
    monkeypatch.setenv("BRIDGE_JWT_AUDIENCE", audience)
    assert not auth.auth_is_configured()
    with pytest.raises(HTTPException) as incomplete:
        asyncio.run(auth.require_bridge_api_key(_request("POST")))
    assert incomplete.value.status_code == 503
