"""Tenant-scoped task state, quota, lease and idempotency hooks.

SQLite is a useful single-host safety net, not a multi-replica queue.  When
``BRIDGE_HA_REQUIRED=true`` readiness rejects this backend until an external
transactional broker (Postgres/Redis equivalent) is provisioned.  The API is
deliberately shaped so that implementation can be swapped without weakening
tenant ownership or idempotency guarantees.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Dict, Optional, Tuple


ACTIVE_STATES = frozenset({"reserved", "queued", "running"})
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "expired"})


class QuotaExceeded(RuntimeError):
    """The tenant has reached its active scan quota."""


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    tenant_id: str
    created_at: float
    request_hash: Optional[str] = None
    status: str = "queued"
    task_type: Optional[str] = None
    lease_owner: Optional[str] = None
    lease_expires_at: Optional[float] = None
    cancel_requested: bool = False


class TaskRegistry:
    def __init__(
        self,
        max_entries: int = 10_000,
        ttl_seconds: int = 86_400,
        db_path: Optional[str] = None,
        max_active_per_tenant: Optional[int] = None,
    ):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self.max_active_per_tenant = max_active_per_tenant or int(
            os.getenv("BRIDGE_MAX_ACTIVE_TASKS_PER_TENANT", "10")
        )
        self.backend = os.getenv("BRIDGE_TASK_BACKEND", "sqlite").strip().lower()
        self.db_path = (db_path if db_path is not None else os.getenv("BRIDGE_TASK_DB", "")).strip()
        self._lock = Lock()
        self._tasks: Dict[str, TaskRecord] = {}
        self._idempotency: Dict[Tuple[str, str], str] = {}
        if self.db_path:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._initialize_db()

    def readiness(self) -> tuple[bool, str]:
        """Report whether this registry can be advertised as production-ready."""

        if self.backend not in {"sqlite", "postgres"}:
            return False, "unsupported task backend"
        if self.backend == "postgres":
            # The adapter is intentionally not faked: until a real shared
            # transactional implementation is injected, readiness is false.
            if os.getenv("BRIDGE_TASK_BACKEND_READY", "false").lower() != "true":
                return False, "shared task backend is not provisioned"
            return True, "shared task backend"
        if os.getenv("BRIDGE_HA_REQUIRED", "true").lower() in {"1", "true", "yes", "on"}:
            return False, "sqlite task registry cannot satisfy multi-replica HA"
        if not self.db_path:
            return False, "task registry has no durable path"
        return True, "single-host durable sqlite"

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_db(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS aig_bridge_tasks (
                    task_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    request_hash TEXT,
                    idempotency_key TEXT,
                    status TEXT NOT NULL DEFAULT 'queued',
                    task_type TEXT,
                    lease_owner TEXT,
                    lease_expires_at REAL,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL DEFAULT 0,
                    UNIQUE (tenant_id, idempotency_key)
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(aig_bridge_tasks)")}
            additions = {
                "status": "TEXT NOT NULL DEFAULT 'queued'",
                "task_type": "TEXT",
                "lease_owner": "TEXT",
                "lease_expires_at": "REAL",
                "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
                "updated_at": "REAL NOT NULL DEFAULT 0",
            }
            for column, definition in additions.items():
                if column not in columns:
                    connection.execute(f"ALTER TABLE aig_bridge_tasks ADD COLUMN {column} {definition}")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_aig_bridge_tasks_created_at ON aig_bridge_tasks(created_at)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_aig_bridge_tasks_tenant_state "
                "ON aig_bridge_tasks(tenant_id, status)"
            )

    def _prune_memory(self, now: float) -> None:
        expired = [
            task_id
            for task_id, record in self._tasks.items()
            if record.status in TERMINAL_STATES and now - record.created_at > self.ttl_seconds
        ]
        for task_id in expired:
            record = self._tasks.pop(task_id, None)
            if record:
                for key, value in list(self._idempotency.items()):
                    if value == task_id:
                        self._idempotency.pop(key, None)
        if len(self._tasks) <= self.max_entries:
            return
        terminal = sorted(
            (record for record in self._tasks.values() if record.status in TERMINAL_STATES),
            key=lambda item: item.created_at,
        )
        for record in terminal[: max(0, len(self._tasks) - self.max_entries)]:
            self._tasks.pop(record.task_id, None)
            for key, value in list(self._idempotency.items()):
                if value == record.task_id:
                    self._idempotency.pop(key, None)

    def _prune_db(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            "DELETE FROM aig_bridge_tasks WHERE status IN ('completed','failed','cancelled','expired') "
            "AND created_at < ?",
            (now - self.ttl_seconds,),
        )
        count = connection.execute("SELECT COUNT(*) FROM aig_bridge_tasks").fetchone()[0]
        if count <= self.max_entries:
            return
        excess = count - self.max_entries
        connection.execute(
            "DELETE FROM aig_bridge_tasks WHERE task_id IN ("
            "SELECT task_id FROM aig_bridge_tasks WHERE status IN ('completed','failed','cancelled','expired') "
            "ORDER BY created_at ASC LIMIT ?)" ,
            (excess,),
        )

    def _row_to_record(self, row: sqlite3.Row) -> TaskRecord:
        return TaskRecord(
            task_id=row["task_id"],
            tenant_id=row["tenant_id"],
            created_at=float(row["created_at"]),
            request_hash=row["request_hash"],
            status=row["status"] or "queued",
            task_type=row["task_type"],
            lease_owner=row["lease_owner"],
            lease_expires_at=row["lease_expires_at"],
            cancel_requested=bool(row["cancel_requested"]),
        )

    def active_count(self, tenant_id: str) -> int:
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, time.time())
                    return int(
                        connection.execute(
                            "SELECT COUNT(*) FROM aig_bridge_tasks WHERE tenant_id = ? AND status IN ('reserved','queued','running')",
                            (tenant_id,),
                        ).fetchone()[0]
                    )
            self._prune_memory(time.time())
            return sum(1 for record in self._tasks.values() if record.tenant_id == tenant_id and record.status in ACTIVE_STATES)

    def admit(self, tenant_id: str, *, limit: Optional[int] = None) -> None:
        """Atomically enforce a tenant active-task quota where SQLite is used."""

        max_active = limit or self.max_active_per_tenant
        with self._lock:
            now = time.time()
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, now)
                    count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM aig_bridge_tasks WHERE tenant_id = ? AND status IN ('reserved','queued','running')",
                            (tenant_id,),
                        ).fetchone()[0]
                    )
                    if count >= max_active:
                        raise QuotaExceeded("tenant task quota exceeded")
                return
            self._prune_memory(now)
            count = sum(1 for record in self._tasks.values() if record.tenant_id == tenant_id and record.status in ACTIVE_STATES)
            if count >= max_active:
                raise QuotaExceeded("tenant task quota exceeded")

    def existing_for_key(self, tenant_id: str, key: Optional[str], request_hash: Optional[str] = None) -> Optional[str]:
        if not key:
            return None
        with self._lock:
            now = time.time()
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, now)
                    row = connection.execute(
                        "SELECT task_id, request_hash FROM aig_bridge_tasks WHERE tenant_id = ? AND idempotency_key = ?",
                        (tenant_id, key),
                    ).fetchone()
                    if row:
                        if request_hash and row["request_hash"] != request_hash:
                            raise ValueError("idempotency key was reused for a different request")
                        return row["task_id"]
                    return None
            self._prune_memory(now)
            task_id = self._idempotency.get((tenant_id, key))
            record = self._tasks.get(task_id) if task_id else None
            if record:
                if request_hash and record.request_hash != request_hash:
                    raise ValueError("idempotency key was reused for a different request")
                return task_id
            return None

    def register(
        self,
        task_id: str,
        tenant_id: str,
        key: Optional[str],
        request_hash: Optional[str] = None,
        *,
        task_type: Optional[str] = None,
        status: str = "queued",
    ) -> str:
        now = time.time()
        with self._lock:
            if self.db_path:
                try:
                    with self._connect() as connection:
                        self._prune_db(connection, now)
                        connection.execute(
                            "INSERT INTO aig_bridge_tasks "
                            "(task_id, tenant_id, created_at, request_hash, idempotency_key, status, task_type, updated_at) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (task_id, tenant_id, now, request_hash, key, status, task_type, now),
                        )
                        return task_id
                except sqlite3.IntegrityError:
                    with self._connect() as connection:
                        row = connection.execute(
                            "SELECT task_id, request_hash FROM aig_bridge_tasks WHERE tenant_id = ? AND idempotency_key = ?",
                            (tenant_id, key),
                        ).fetchone()
                    if row and request_hash and row["request_hash"] != request_hash:
                        raise ValueError("idempotency key was reused for a different request")
                    if row:
                        return row["task_id"]
                    raise

            self._prune_memory(now)
            self._tasks[task_id] = TaskRecord(task_id, tenant_id, now, request_hash, status=status, task_type=task_type)
            if key:
                self._idempotency[(tenant_id, key)] = task_id
            return task_id

    def update_status(self, task_id: str, tenant_id: str, status: str) -> None:
        if status not in ACTIVE_STATES | TERMINAL_STATES:
            raise ValueError("invalid task status")
        now = time.time()
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET status = ?, updated_at = ? WHERE task_id = ? AND tenant_id = ?",
                        (status, now, task_id, tenant_id),
                    )
                    if result.rowcount != 1:
                        raise KeyError(task_id)
                return
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id:
                raise KeyError(task_id)
            self._tasks[task_id] = TaskRecord(**{**record.__dict__, "status": status})

    def acquire_lease(self, task_id: str, tenant_id: str, owner: str, ttl_seconds: int = 60) -> bool:
        expires = time.time() + max(1, min(ttl_seconds, 3_600))
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET lease_owner = ?, lease_expires_at = ?, status = 'running', updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ? AND status IN ('reserved','queued','running') "
                        "AND (lease_expires_at IS NULL OR lease_expires_at < ? OR lease_owner = ?)",
                        (owner, expires, time.time(), task_id, tenant_id, time.time(), owner),
                    )
                    return result.rowcount == 1
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id or record.status not in ACTIVE_STATES:
                return False
            if record.lease_expires_at and record.lease_expires_at >= time.time() and record.lease_owner != owner:
                return False
            self._tasks[task_id] = TaskRecord(**{**record.__dict__, "status": "running", "lease_owner": owner, "lease_expires_at": expires})
            return True

    def renew_lease(self, task_id: str, tenant_id: str, owner: str, ttl_seconds: int = 60) -> bool:
        expires = time.time() + max(1, min(ttl_seconds, 3_600))
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET lease_expires_at = ?, updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ? AND lease_owner = ? AND status IN ('reserved','queued','running')",
                        (expires, time.time(), task_id, tenant_id, owner),
                    )
                    return result.rowcount == 1
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id or record.lease_owner != owner or record.status not in ACTIVE_STATES:
                return False
            self._tasks[task_id] = TaskRecord(**{**record.__dict__, "lease_expires_at": expires})
            return True

    def request_cancel(self, task_id: str, tenant_id: str) -> bool:
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET cancel_requested = 1, updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ? AND status IN ('reserved','queued','running')",
                        (time.time(), task_id, tenant_id),
                    )
                    return result.rowcount == 1
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id or record.status not in ACTIVE_STATES:
                return False
            self._tasks[task_id] = TaskRecord(**{**record.__dict__, "cancel_requested": True})
            return True

    def reclaim_expired(self) -> int:
        now = time.time()
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET status = 'queued', lease_owner = NULL, lease_expires_at = NULL, updated_at = ? "
                        "WHERE status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
                        (now, now),
                    )
                    return result.rowcount
            count = 0
            for task_id, record in list(self._tasks.items()):
                if record.status == "running" and record.lease_expires_at and record.lease_expires_at < now:
                    self._tasks[task_id] = TaskRecord(**{**record.__dict__, "status": "queued", "lease_owner": None, "lease_expires_at": None})
                    count += 1
            return count

    def record_for(self, task_id: str, tenant_id: str) -> TaskRecord:
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, time.time())
                    row = connection.execute(
                        "SELECT * FROM aig_bridge_tasks WHERE task_id = ? AND tenant_id = ?",
                        (task_id, tenant_id),
                    ).fetchone()
                if row is None:
                    raise KeyError(task_id)
                return self._row_to_record(row)
            self._prune_memory(time.time())
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id:
                raise KeyError(task_id)
            return record

    def assert_owner(self, task_id: str, tenant_id: str) -> None:
        self.record_for(task_id, tenant_id)


task_registry = TaskRegistry()

