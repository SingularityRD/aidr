"""Atomic task-registry contracts, including optional live PostgreSQL races."""

from __future__ import annotations

import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from app.task_registry import (
    QuotaExceeded,
    SubmissionInProgress,
    TaskRegistry,
)


def _race(workers, operation):
    barrier = Barrier(workers)

    def run(index):
        barrier.wait()
        try:
            return operation(index)
        except (QuotaExceeded, SubmissionInProgress) as exc:
            return type(exc)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(run, range(workers)))


def test_shared_sqlite_reservation_serializes_idempotency_and_quota(tmp_path):
    """Deterministically exercise the same reservation API without external services."""

    db_path = str(tmp_path / "registry.db")
    idem_registries = [
        TaskRegistry(db_path=db_path, backend="sqlite", max_active_per_tenant=10)
        for _ in range(8)
    ]

    def same_key(index):
        return idem_registries[index].reserve_submission(
            "tenant-idem", "same-key", "same-hash"
        )

    results = _race(8, same_key)
    reservations = [result for result in results if not isinstance(result, type)]
    assert len(reservations) == 1
    assert results.count(SubmissionInProgress) == 7

    quota_registries = [
        TaskRegistry(db_path=db_path, backend="sqlite", max_active_per_tenant=1)
        for _ in range(8)
    ]

    def tenant_quota(index):
        return quota_registries[index].reserve_submission(
            "tenant-quota", f"key-{index}", f"hash-{index}"
        )

    results = _race(8, tenant_quota)
    reservations = [result for result in results if not isinstance(result, type)]
    assert len(reservations) == 1
    assert results.count(QuotaExceeded) == 7


def test_shared_sqlite_lease_has_one_winner(tmp_path):
    db_path = str(tmp_path / "registry.db")
    TaskRegistry(db_path=db_path, backend="sqlite").register(
        "task-lease", "tenant-lease", None
    )
    registries = [TaskRegistry(db_path=db_path, backend="sqlite") for _ in range(8)]

    def acquire(index):
        return registries[index].acquire_lease(
            "task-lease", "tenant-lease", f"worker-{index}"
        )

    assert _race(8, acquire).count(True) == 1


def test_ambiguous_reservation_is_never_expired_automatically(tmp_path):
    db_path = str(tmp_path / "registry.db")
    registry = TaskRegistry(db_path=db_path, backend="sqlite", ttl_seconds=1)
    reservation = registry.reserve_submission("tenant-a", "key-a", "hash-a")
    with registry._connect() as connection:
        connection.execute(
            "UPDATE aig_bridge_tasks SET created_at = 0, updated_at = 0 WHERE task_id = ?",
            (reservation.token,),
        )

    assert registry.active_count("tenant-a") == 1
    with pytest.raises(SubmissionInProgress):
        registry.reserve_submission("tenant-a", "key-a", "hash-a")


@pytest.mark.skipif(
    not os.getenv("AIG_BRIDGE_TEST_POSTGRES_DSN"),
    reason="set AIG_BRIDGE_TEST_POSTGRES_DSN for live two-session PostgreSQL races",
)
def test_live_postgres_cross_instance_races():
    """Run against disposable PostgreSQL; applies only the component migration."""

    import psycopg

    dsn = os.environ["AIG_BRIDGE_TEST_POSTGRES_DSN"]
    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "001_postgres_task_registry.sql"
    ).read_text(encoding="utf-8")
    with psycopg.connect(dsn) as connection:
        connection.execute(migration)

    run = uuid.uuid4().hex

    def registry(limit=10):
        return TaskRegistry(
            backend="postgres",
            postgres_dsn=dsn,
            max_active_per_tenant=limit,
        )

    assert registry().readiness() == (True, "shared postgres task registry")

    idem_tenant = f"test-idem-{run}"
    results = _race(
        8,
        lambda _index: registry().reserve_submission(
            idem_tenant, "same-key", "same-hash"
        ),
    )
    assert sum(not isinstance(result, type) for result in results) == 1
    assert results.count(SubmissionInProgress) == 7

    quota_tenant = f"test-quota-{run}"
    results = _race(
        8,
        lambda index: registry(1).reserve_submission(
            quota_tenant, f"key-{index}", f"hash-{index}"
        ),
    )
    assert sum(not isinstance(result, type) for result in results) == 1
    assert results.count(QuotaExceeded) == 7

    register_idem_tenant = f"test-register-idem-{run}"
    results = _race(
        8,
        lambda index: registry().register(
            f"task-register-{run}-{index}",
            register_idem_tenant,
            "same-key",
            "same-hash",
        ),
    )
    assert len(set(results)) == 1

    register_quota_tenant = f"test-register-quota-{run}"
    results = _race(
        8,
        lambda index: registry(1).register(
            f"task-quota-{run}-{index}",
            register_quota_tenant,
            f"key-{index}",
            f"hash-{index}",
        ),
    )
    assert sum(isinstance(result, str) for result in results) == 1
    assert results.count(QuotaExceeded) == 7

    lease_tenant = f"test-lease-{run}"
    registry().register(f"task-{run}", lease_tenant, None)
    results = _race(
        8,
        lambda index: registry().acquire_lease(
            f"task-{run}", lease_tenant, f"worker-{index}"
        ),
    )
    assert results.count(True) == 1

    # /metrics depth gauge: cross-tenant, fixed state keys, read-only.
    depth = registry().active_counts_by_status()
    assert set(depth) == {"reserved", "queued", "running"}
    assert sum(depth.values()) >= 4

    with psycopg.connect(dsn) as connection:
        connection.execute(
            "DELETE FROM aig_bridge_tasks WHERE tenant_id = ANY(%s)",
            (
                [
                    idem_tenant,
                    quota_tenant,
                    register_idem_tenant,
                    register_quota_tenant,
                    lease_tenant,
                ],
            ),
        )


@pytest.mark.skipif(
    not os.getenv("AIG_BRIDGE_TEST_POSTGRES_DSN"),
    reason="set AIG_BRIDGE_TEST_POSTGRES_DSN for live PostgreSQL JWT replay races",
)
def test_live_postgres_jwt_replay_cross_instance_races():
    from app.auth import ReplayStore
    import psycopg

    dsn = os.environ["AIG_BRIDGE_TEST_POSTGRES_DSN"]
    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "002_postgres_jwt_replay.sql"
    ).read_text(encoding="utf-8")
    with psycopg.connect(dsn) as connection:
        connection.execute(migration)

    jti = f"test-replay-{uuid.uuid4().hex}"
    store = lambda: ReplayStore(postgres_dsn=dsn)
    assert store().readiness() == (True, "shared postgres JWT replay store")
    results = _race(8, lambda _index: store().consume(jti, int(time.time()) + 60))
    assert results.count(True) == 1
    assert results.count(False) == 7
    assert store().consume(jti, int(time.time()) + 60) is False
    with psycopg.connect(dsn) as connection:
        connection.execute("DELETE FROM aig_bridge_jwt_replay WHERE jti = %s", (jti,))
