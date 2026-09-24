"""Tenant-scoped task state, quota, lease and idempotency registry.

SQLite is a single-host safety net. PostgreSQL is the shared multi-replica
backend and relies on the checked-in migration, database constraints and
transaction-scoped advisory locks for cross-instance correctness.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Iterator, Mapping, Optional, Tuple


ACTIVE_STATES = frozenset({"reserved", "queued", "running"})
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "expired"})
_POSTGRES_SCHEMA_VERSION = 1
_TENANT_LOCK_SALT = 260922


class QuotaExceeded(RuntimeError):
    """The tenant has reached its active scan quota."""


class SubmissionInProgress(RuntimeError):
    """Another replica is submitting the same idempotent request."""


class TaskRegistryUnavailable(RuntimeError):
    """The configured shared task registry cannot be reached safely."""


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


@dataclass(frozen=True)
class SubmissionReservation:
    token: str
    tenant_id: str
    task_id: Optional[str] = None
    is_new: bool = True


def _value(row: Any, name: str, index: int = 0) -> Any:
    return row[name] if isinstance(row, Mapping) else row[index]


class TaskRegistry:
    def __init__(
        self,
        max_entries: int = 10_000,
        ttl_seconds: int = 86_400,
        db_path: Optional[str] = None,
        max_active_per_tenant: Optional[int] = None,
        *,
        backend: Optional[str] = None,
        postgres_dsn: Optional[str] = None,
        postgres_connect: Optional[Callable[[], Any]] = None,
    ):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self.max_active_per_tenant = max_active_per_tenant or int(
            os.getenv("BRIDGE_MAX_ACTIVE_TASKS_PER_TENANT", "10")
        )
        self.backend = (backend or os.getenv("BRIDGE_TASK_BACKEND", "sqlite")).strip().lower()
        self.db_path = (db_path if db_path is not None else os.getenv("BRIDGE_TASK_DB", "")).strip()
        self.postgres_dsn = (
            postgres_dsn
            if postgres_dsn is not None
            else os.getenv("BRIDGE_TASK_POSTGRES_DSN", "")
        ).strip()
        self._postgres_connect_override = postgres_connect
        self._lock = Lock()
        self._tasks: Dict[str, TaskRecord] = {}
        self._idempotency: Dict[Tuple[str, str], str] = {}
        if self.backend == "sqlite" and self.db_path:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._initialize_db()

    def readiness(self) -> tuple[bool, str]:
        """Probe the configured backend instead of trusting a readiness flag."""

        if self.backend not in {"sqlite", "postgres"}:
            return False, "unsupported task backend"
        if self.backend == "postgres":
            if not self.postgres_dsn and self._postgres_connect_override is None:
                return False, "postgres task registry DSN is not configured"
            try:
                with self._raw_postgres_connection() as connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT schema_version FROM aig_bridge_registry_meta WHERE singleton = TRUE"
                        )
                        row = cursor.fetchone()
                        if row is None or int(_value(row, "schema_version")) != _POSTGRES_SCHEMA_VERSION:
                            return False, "postgres task registry migration is not current"
                        cursor.execute(
                            "SELECT has_table_privilege(current_user, 'public.aig_bridge_tasks', "
                            "'SELECT,INSERT,UPDATE,DELETE') AS permitted"
                        )
                        if not bool(_value(cursor.fetchone(), "permitted")):
                            return False, "postgres task registry role lacks required privileges"
                        cursor.execute("SELECT 1 FROM aig_bridge_tasks LIMIT 1")
                return True, "shared postgres task registry"
            except Exception:
                return False, "postgres task registry is unavailable or not migrated"
        if os.getenv("BRIDGE_HA_REQUIRED", "true").lower() in {"1", "true", "yes", "on"}:
            return False, "sqlite task registry cannot satisfy multi-replica HA"
        if not self.db_path:
            return False, "task registry has no durable path"
        return True, "single-host durable sqlite"

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    def _postgres_connect(self) -> Any:
        if self._postgres_connect_override is not None:
            return self._postgres_connect_override()
        if not self.postgres_dsn:
            raise TaskRegistryUnavailable("postgres task registry DSN is not configured")
        import psycopg
        from psycopg.rows import dict_row

        connect_timeout = max(
            1, min(int(os.getenv("BRIDGE_TASK_DB_CONNECT_TIMEOUT_SECONDS", "3")), 30)
        )
        statement_timeout = max(
            100, min(int(os.getenv("BRIDGE_TASK_DB_STATEMENT_TIMEOUT_MS", "5000")), 60_000)
        )
        return psycopg.connect(
            self.postgres_dsn,
            connect_timeout=connect_timeout,
            options=(
                f"-c statement_timeout={statement_timeout} "
                f"-c lock_timeout={statement_timeout} -c search_path=pg_catalog,public"
            ),
            row_factory=dict_row,
        )

    @contextmanager
    def _raw_postgres_connection(self) -> Iterator[Any]:
        connection = self._postgres_connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def _postgres_connection(self) -> Iterator[Any]:
        try:
            with self._raw_postgres_connection() as connection:
                yield connection
        except (KeyError, QuotaExceeded, SubmissionInProgress, TaskRegistryUnavailable, ValueError):
            raise
        except Exception as exc:
            raise TaskRegistryUnavailable("shared task registry operation failed") from exc

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

    def _remove_memory(self, task_id: str) -> None:
        self._tasks.pop(task_id, None)
        for key, value in list(self._idempotency.items()):
            if value == task_id:
                self._idempotency.pop(key, None)

    def _prune_memory(self, now: float) -> None:
        expired = [
            task_id
            for task_id, record in self._tasks.items()
            if (
                record.status in TERMINAL_STATES
                and now - record.created_at > self.ttl_seconds
            )
        ]
        for task_id in expired:
            self._remove_memory(task_id)
        if len(self._tasks) > self.max_entries:
            terminal = sorted(
                (record for record in self._tasks.values() if record.status in TERMINAL_STATES),
                key=lambda item: item.created_at,
            )
            for record in terminal[: len(self._tasks) - self.max_entries]:
                self._remove_memory(record.task_id)

    def _prune_db(self, connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            "DELETE FROM aig_bridge_tasks WHERE "
            "status IN ('completed','failed','cancelled','expired') AND created_at < ?",
            (now - self.ttl_seconds,),
        )
        count = connection.execute("SELECT COUNT(*) FROM aig_bridge_tasks").fetchone()[0]
        if count > self.max_entries:
            connection.execute(
                "DELETE FROM aig_bridge_tasks WHERE task_id IN ("
                "SELECT task_id FROM aig_bridge_tasks "
                "WHERE status IN ('completed','failed','cancelled','expired') "
                "ORDER BY created_at ASC LIMIT ?)",
                (count - self.max_entries,),
            )

    def _prune_postgres(self, cursor: Any, now: float) -> None:
        cursor.execute(
            "DELETE FROM aig_bridge_tasks WHERE "
            "status IN ('completed','failed','cancelled','expired') AND created_at < %s",
            (now - self.ttl_seconds,),
        )
        cursor.execute("SELECT COUNT(*) AS count FROM aig_bridge_tasks")
        count = int(_value(cursor.fetchone(), "count"))
        if count > self.max_entries:
            cursor.execute(
                "DELETE FROM aig_bridge_tasks WHERE task_id IN ("
                "SELECT task_id FROM aig_bridge_tasks "
                "WHERE status IN ('completed','failed','cancelled','expired') "
                "ORDER BY created_at ASC LIMIT %s)",
                (count - self.max_entries,),
            )

    @staticmethod
    def _lock_tenant(cursor: Any, tenant_id: str) -> None:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, %s))",
            (tenant_id, _TENANT_LOCK_SALT),
        )

    @staticmethod
    def _row_to_record(row: Any) -> TaskRecord:
        return TaskRecord(
            task_id=_value(row, "task_id", 0),
            tenant_id=_value(row, "tenant_id", 1),
            created_at=float(_value(row, "created_at", 2)),
            request_hash=_value(row, "request_hash", 3),
            status=_value(row, "status", 4) or "queued",
            task_type=_value(row, "task_type", 5),
            lease_owner=_value(row, "lease_owner", 6),
            lease_expires_at=_value(row, "lease_expires_at", 7),
            cancel_requested=bool(_value(row, "cancel_requested", 8)),
        )

    def reserve_submission(
        self,
        tenant_id: str,
        key: Optional[str],
        request_hash: Optional[str],
        *,
        task_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> SubmissionReservation:
        """Atomically claim an idempotency key and one tenant quota slot."""

        max_active = limit or self.max_active_per_tenant
        now = time.time()
        token = f"reservation:{uuid.uuid4()}"
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    self._lock_tenant(cursor, tenant_id)
                    self._prune_postgres(cursor, now)
                    existing = self._reserved_or_existing_postgres(
                        cursor, tenant_id, key, request_hash
                    )
                    if existing:
                        return existing
                    cursor.execute(
                        "SELECT COUNT(*) AS count FROM aig_bridge_tasks "
                        "WHERE tenant_id = %s AND status IN ('reserved','queued','running')",
                        (tenant_id,),
                    )
                    if int(_value(cursor.fetchone(), "count")) >= max_active:
                        raise QuotaExceeded("tenant task quota exceeded")
                    cursor.execute(
                        "INSERT INTO aig_bridge_tasks "
                        "(task_id, tenant_id, created_at, request_hash, idempotency_key, status, task_type, updated_at) "
                        "VALUES (%s, %s, %s, %s, %s, 'reserved', %s, %s)",
                        (token, tenant_id, now, request_hash, key, task_type, now),
                    )
            return SubmissionReservation(token, tenant_id)

        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._prune_db(connection, now)
                    if key:
                        row = connection.execute(
                            "SELECT task_id, request_hash, status FROM aig_bridge_tasks "
                            "WHERE tenant_id = ? AND idempotency_key = ?",
                            (tenant_id, key),
                        ).fetchone()
                        existing = self._reserved_or_existing_row(
                            row, tenant_id, request_hash
                        )
                        if existing:
                            return existing
                    count = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM aig_bridge_tasks WHERE tenant_id = ? "
                            "AND status IN ('reserved','queued','running')",
                            (tenant_id,),
                        ).fetchone()[0]
                    )
                    if count >= max_active:
                        raise QuotaExceeded("tenant task quota exceeded")
                    connection.execute(
                        "INSERT INTO aig_bridge_tasks "
                        "(task_id, tenant_id, created_at, request_hash, idempotency_key, status, task_type, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, 'reserved', ?, ?)",
                        (token, tenant_id, now, request_hash, key, task_type, now),
                    )
                return SubmissionReservation(token, tenant_id)

            self._prune_memory(now)
            if key:
                existing_id = self._idempotency.get((tenant_id, key))
                existing = self._tasks.get(existing_id) if existing_id else None
                if existing:
                    if request_hash and existing.request_hash != request_hash:
                        raise ValueError("idempotency key was reused for a different request")
                    if existing.status == "reserved" and existing.task_id.startswith("reservation:"):
                        raise SubmissionInProgress("idempotent task submission is in progress")
                    return SubmissionReservation(existing.task_id, tenant_id, existing.task_id, False)
            if sum(
                1
                for record in self._tasks.values()
                if record.tenant_id == tenant_id and record.status in ACTIVE_STATES
            ) >= max_active:
                raise QuotaExceeded("tenant task quota exceeded")
            self._tasks[token] = TaskRecord(
                token, tenant_id, now, request_hash, status="reserved", task_type=task_type
            )
            if key:
                self._idempotency[(tenant_id, key)] = token
            return SubmissionReservation(token, tenant_id)

    def _reserved_or_existing_postgres(
        self,
        cursor: Any,
        tenant_id: str,
        key: Optional[str],
        request_hash: Optional[str],
    ) -> Optional[SubmissionReservation]:
        if not key:
            return None
        cursor.execute(
            "SELECT task_id, request_hash, status FROM aig_bridge_tasks "
            "WHERE tenant_id = %s AND idempotency_key = %s",
            (tenant_id, key),
        )
        return self._reserved_or_existing_row(cursor.fetchone(), tenant_id, request_hash)

    @staticmethod
    def _reserved_or_existing_row(
        row: Any,
        tenant_id: str,
        request_hash: Optional[str],
    ) -> Optional[SubmissionReservation]:
        if not row:
            return None
        if request_hash and _value(row, "request_hash", 1) != request_hash:
            raise ValueError("idempotency key was reused for a different request")
        task_id = str(_value(row, "task_id", 0))
        if _value(row, "status", 2) == "reserved" and task_id.startswith("reservation:"):
            raise SubmissionInProgress("idempotent task submission is in progress")
        return SubmissionReservation(task_id, tenant_id, task_id, False)

    def finalize_submission(self, reservation: SubmissionReservation, task_id: str) -> str:
        if not reservation.is_new:
            if not reservation.task_id:
                raise ValueError("existing reservation has no task id")
            return reservation.task_id
        now = time.time()
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE aig_bridge_tasks SET task_id = %s, status = 'queued', updated_at = %s "
                        "WHERE task_id = %s AND tenant_id = %s AND status = 'reserved' RETURNING task_id",
                        (task_id, now, reservation.token, reservation.tenant_id),
                    )
                    if cursor.fetchone() is None:
                        raise KeyError(reservation.token)
            return task_id
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET task_id = ?, status = 'queued', updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ? AND status = 'reserved'",
                        (task_id, now, reservation.token, reservation.tenant_id),
                    )
                    if result.rowcount != 1:
                        raise KeyError(reservation.token)
                return task_id
            record = self._tasks.pop(reservation.token, None)
            if record is None or record.tenant_id != reservation.tenant_id or record.status != "reserved":
                raise KeyError(reservation.token)
            self._tasks[task_id] = TaskRecord(
                **{**record.__dict__, "task_id": task_id, "status": "queued"}
            )
            for key, value in list(self._idempotency.items()):
                if value == reservation.token:
                    self._idempotency[key] = task_id
            return task_id

    def release_submission(self, reservation: SubmissionReservation) -> None:
        if not reservation.is_new:
            return
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM aig_bridge_tasks "
                        "WHERE task_id = %s AND tenant_id = %s AND status = 'reserved'",
                        (reservation.token, reservation.tenant_id),
                    )
            return
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    connection.execute(
                        "DELETE FROM aig_bridge_tasks "
                        "WHERE task_id = ? AND tenant_id = ? AND status = 'reserved'",
                        (reservation.token, reservation.tenant_id),
                    )
            else:
                self._remove_memory(reservation.token)

    def active_count(self, tenant_id: str) -> int:
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    self._prune_postgres(cursor, time.time())
                    cursor.execute(
                        "SELECT COUNT(*) AS count FROM aig_bridge_tasks "
                        "WHERE tenant_id = %s AND status IN ('reserved','queued','running')",
                        (tenant_id,),
                    )
                    return int(_value(cursor.fetchone(), "count"))
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, time.time())
                    return int(
                        connection.execute(
                            "SELECT COUNT(*) FROM aig_bridge_tasks WHERE tenant_id = ? "
                            "AND status IN ('reserved','queued','running')",
                            (tenant_id,),
                        ).fetchone()[0]
                    )
            self._prune_memory(time.time())
            return sum(
                record.tenant_id == tenant_id and record.status in ACTIVE_STATES
                for record in self._tasks.values()
            )

    def admit(self, tenant_id: str, *, limit: Optional[int] = None) -> None:
        """Check quota; register/reserve performs the authoritative locked check."""

        if self.active_count(tenant_id) >= (limit or self.max_active_per_tenant):
            raise QuotaExceeded("tenant task quota exceeded")

    def existing_for_key(
        self,
        tenant_id: str,
        key: Optional[str],
        request_hash: Optional[str] = None,
    ) -> Optional[str]:
        if not key:
            return None
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    self._prune_postgres(cursor, time.time())
                    cursor.execute(
                        "SELECT task_id, request_hash FROM aig_bridge_tasks "
                        "WHERE tenant_id = %s AND idempotency_key = %s",
                        (tenant_id, key),
                    )
                    row = cursor.fetchone()
                    if row:
                        if request_hash and _value(row, "request_hash", 1) != request_hash:
                            raise ValueError("idempotency key was reused for a different request")
                        task_id = str(_value(row, "task_id", 0))
                        return None if task_id.startswith("reservation:") else task_id
                    return None
        with self._lock:
            now = time.time()
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, now)
                    row = connection.execute(
                        "SELECT task_id, request_hash FROM aig_bridge_tasks "
                        "WHERE tenant_id = ? AND idempotency_key = ?",
                        (tenant_id, key),
                    ).fetchone()
                    if row:
                        if request_hash and row["request_hash"] != request_hash:
                            raise ValueError("idempotency key was reused for a different request")
                        return None if row["task_id"].startswith("reservation:") else row["task_id"]
                    return None
            self._prune_memory(now)
            task_id = self._idempotency.get((tenant_id, key))
            record = self._tasks.get(task_id) if task_id else None
            if not record:
                return None
            if request_hash and record.request_hash != request_hash:
                raise ValueError("idempotency key was reused for a different request")
            return None if record.task_id.startswith("reservation:") else record.task_id

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
        if status not in ACTIVE_STATES | TERMINAL_STATES:
            raise ValueError("invalid task status")
        now = time.time()
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    self._lock_tenant(cursor, tenant_id)
                    self._prune_postgres(cursor, now)
                    existing = self._existing_registration_postgres(
                        cursor, tenant_id, key, request_hash
                    )
                    if existing:
                        return existing
                    if status in ACTIVE_STATES:
                        cursor.execute(
                            "SELECT COUNT(*) AS count FROM aig_bridge_tasks "
                            "WHERE tenant_id = %s AND status IN ('reserved','queued','running')",
                            (tenant_id,),
                        )
                        if int(_value(cursor.fetchone(), "count")) >= self.max_active_per_tenant:
                            raise QuotaExceeded("tenant task quota exceeded")
                    cursor.execute(
                        "INSERT INTO aig_bridge_tasks "
                        "(task_id, tenant_id, created_at, request_hash, idempotency_key, status, task_type, updated_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT DO NOTHING RETURNING task_id",
                        (task_id, tenant_id, now, request_hash, key, status, task_type, now),
                    )
                    if cursor.fetchone() is not None:
                        return task_id
                    cursor.execute(
                        "SELECT task_id, tenant_id, request_hash FROM aig_bridge_tasks "
                        "WHERE task_id = %s OR (tenant_id = %s AND idempotency_key = %s)",
                        (task_id, tenant_id, key),
                    )
                    row = cursor.fetchone()
                    if row and _value(row, "tenant_id", 1) == tenant_id:
                        if request_hash and _value(row, "request_hash", 2) != request_hash:
                            raise ValueError("idempotency key was reused for a different request")
                        return str(_value(row, "task_id", 0))
                    raise ValueError("task id is already registered to another tenant")
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
                            "SELECT task_id, request_hash, status FROM aig_bridge_tasks "
                            "WHERE tenant_id = ? AND idempotency_key = ?",
                            (tenant_id, key),
                        ).fetchone()
                    if row and row["status"] == "reserved" and row["task_id"].startswith("reservation:"):
                        raise SubmissionInProgress("idempotent task submission is in progress")
                    if row and request_hash and row["request_hash"] != request_hash:
                        raise ValueError("idempotency key was reused for a different request")
                    if row:
                        return row["task_id"]
                    raise
            self._prune_memory(now)
            self._tasks[task_id] = TaskRecord(
                task_id, tenant_id, now, request_hash, status=status, task_type=task_type
            )
            if key:
                self._idempotency[(tenant_id, key)] = task_id
            return task_id

    @staticmethod
    def _existing_registration_postgres(
        cursor: Any,
        tenant_id: str,
        key: Optional[str],
        request_hash: Optional[str],
    ) -> Optional[str]:
        if not key:
            return None
        cursor.execute(
            "SELECT task_id, request_hash, status FROM aig_bridge_tasks "
            "WHERE tenant_id = %s AND idempotency_key = %s",
            (tenant_id, key),
        )
        row = cursor.fetchone()
        if not row:
            return None
        if _value(row, "status", 2) == "reserved" and str(_value(row, "task_id", 0)).startswith("reservation:"):
            raise SubmissionInProgress("idempotent task submission is in progress")
        if request_hash and _value(row, "request_hash", 1) != request_hash:
            raise ValueError("idempotency key was reused for a different request")
        return str(_value(row, "task_id", 0))

    def update_status(self, task_id: str, tenant_id: str, status: str) -> None:
        if status not in ACTIVE_STATES | TERMINAL_STATES:
            raise ValueError("invalid task status")
        now = time.time()
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE aig_bridge_tasks SET status = %s, updated_at = %s "
                        "WHERE task_id = %s AND tenant_id = %s RETURNING task_id",
                        (status, now, task_id, tenant_id),
                    )
                    if cursor.fetchone() is None:
                        raise KeyError(task_id)
            return
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET status = ?, updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ?",
                        (status, now, task_id, tenant_id),
                    )
                    if result.rowcount != 1:
                        raise KeyError(task_id)
            else:
                record = self._tasks.get(task_id)
                if record is None or record.tenant_id != tenant_id:
                    raise KeyError(task_id)
                self._tasks[task_id] = TaskRecord(**{**record.__dict__, "status": status})

    def acquire_lease(
        self,
        task_id: str,
        tenant_id: str,
        owner: str,
        ttl_seconds: int = 60,
    ) -> bool:
        now = time.time()
        expires = now + max(1, min(ttl_seconds, 3_600))
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE aig_bridge_tasks SET lease_owner = %s, lease_expires_at = %s, "
                        "status = 'running', updated_at = %s WHERE task_id = %s AND tenant_id = %s "
                        "AND status IN ('reserved','queued','running') "
                        "AND (lease_expires_at IS NULL OR lease_expires_at < %s OR lease_owner = %s) "
                        "RETURNING task_id",
                        (owner, expires, now, task_id, tenant_id, now, owner),
                    )
                    return cursor.fetchone() is not None
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET lease_owner = ?, lease_expires_at = ?, "
                        "status = 'running', updated_at = ? WHERE task_id = ? AND tenant_id = ? "
                        "AND status IN ('reserved','queued','running') "
                        "AND (lease_expires_at IS NULL OR lease_expires_at < ? OR lease_owner = ?)",
                        (owner, expires, now, task_id, tenant_id, now, owner),
                    )
                    return result.rowcount == 1
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id or record.status not in ACTIVE_STATES:
                return False
            if record.lease_expires_at and record.lease_expires_at >= now and record.lease_owner != owner:
                return False
            self._tasks[task_id] = TaskRecord(
                **{
                    **record.__dict__,
                    "status": "running",
                    "lease_owner": owner,
                    "lease_expires_at": expires,
                }
            )
            return True

    def renew_lease(
        self,
        task_id: str,
        tenant_id: str,
        owner: str,
        ttl_seconds: int = 60,
    ) -> bool:
        now = time.time()
        expires = now + max(1, min(ttl_seconds, 3_600))
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE aig_bridge_tasks SET lease_expires_at = %s, updated_at = %s "
                        "WHERE task_id = %s AND tenant_id = %s AND lease_owner = %s "
                        "AND status IN ('reserved','queued','running') RETURNING task_id",
                        (expires, now, task_id, tenant_id, owner),
                    )
                    return cursor.fetchone() is not None
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET lease_expires_at = ?, updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ? AND lease_owner = ? "
                        "AND status IN ('reserved','queued','running')",
                        (expires, now, task_id, tenant_id, owner),
                    )
                    return result.rowcount == 1
            record = self._tasks.get(task_id)
            if (
                record is None
                or record.tenant_id != tenant_id
                or record.lease_owner != owner
                or record.status not in ACTIVE_STATES
            ):
                return False
            self._tasks[task_id] = TaskRecord(
                **{**record.__dict__, "lease_expires_at": expires}
            )
            return True

    def request_cancel(self, task_id: str, tenant_id: str) -> bool:
        now = time.time()
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE aig_bridge_tasks SET cancel_requested = TRUE, updated_at = %s "
                        "WHERE task_id = %s AND tenant_id = %s "
                        "AND status IN ('reserved','queued','running') RETURNING task_id",
                        (now, task_id, tenant_id),
                    )
                    return cursor.fetchone() is not None
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET cancel_requested = 1, updated_at = ? "
                        "WHERE task_id = ? AND tenant_id = ? "
                        "AND status IN ('reserved','queued','running')",
                        (now, task_id, tenant_id),
                    )
                    return result.rowcount == 1
            record = self._tasks.get(task_id)
            if record is None or record.tenant_id != tenant_id or record.status not in ACTIVE_STATES:
                return False
            self._tasks[task_id] = TaskRecord(
                **{**record.__dict__, "cancel_requested": True}
            )
            return True

    def reclaim_expired(self) -> int:
        now = time.time()
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE aig_bridge_tasks SET status = 'queued', lease_owner = NULL, "
                        "lease_expires_at = NULL, updated_at = %s WHERE status = 'running' "
                        "AND lease_expires_at IS NOT NULL AND lease_expires_at < %s RETURNING task_id",
                        (now, now),
                    )
                    return len(cursor.fetchall())
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    result = connection.execute(
                        "UPDATE aig_bridge_tasks SET status = 'queued', lease_owner = NULL, "
                        "lease_expires_at = NULL, updated_at = ? WHERE status = 'running' "
                        "AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
                        (now, now),
                    )
                    return result.rowcount
            count = 0
            for task_id, record in list(self._tasks.items()):
                if record.status == "running" and record.lease_expires_at and record.lease_expires_at < now:
                    self._tasks[task_id] = TaskRecord(
                        **{
                            **record.__dict__,
                            "status": "queued",
                            "lease_owner": None,
                            "lease_expires_at": None,
                        }
                    )
                    count += 1
            return count

    def record_for(self, task_id: str, tenant_id: str) -> TaskRecord:
        select = (
            "SELECT task_id, tenant_id, created_at, request_hash, status, task_type, "
            "lease_owner, lease_expires_at, cancel_requested FROM aig_bridge_tasks "
        )
        if self.backend == "postgres":
            with self._postgres_connection() as connection:
                with connection.cursor() as cursor:
                    self._prune_postgres(cursor, time.time())
                    cursor.execute(
                        select + "WHERE task_id = %s AND tenant_id = %s",
                        (task_id, tenant_id),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise KeyError(task_id)
                    return self._row_to_record(row)
        with self._lock:
            if self.db_path:
                with self._connect() as connection:
                    self._prune_db(connection, time.time())
                    row = connection.execute(
                        select + "WHERE task_id = ? AND tenant_id = ?",
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
