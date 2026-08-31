from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .db import Database

from .protocol import capabilities_for_profile


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def as_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def hash_opaque(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RemoteAgentStore:
    """SQLite-backed durable registry for remote agent devices."""

    def __init__(self, database_path: str):
        if database_path.startswith("sqlite:///"):
            database_path = database_path[len("sqlite:///") :]
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=10,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 10000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator["RemoteAgentStore"]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")

    def _execute(
        self,
        statement: str,
        parameters: tuple[Any, ...] = (),
    ):
        return self._connection.execute(statement, parameters)

    def _fetchone(self, statement: str, parameters: tuple[Any, ...] = ()):
        row = self._execute(statement, parameters).fetchone()
        return dict(row) if row is not None else None

    def _fetchall(self, statement: str, parameters: tuple[Any, ...] = ()):
        return [
            dict(row)
            for row in self._execute(statement, parameters).fetchall()
        ]

    def _migrate(self) -> None:
        migrations_dir = (
            Path(__file__).resolve().parent / "migrations" / "sqlite"
        )
        if not migrations_dir.is_dir():
            raise RuntimeError(
                "Remote Agent migration directory is missing"
            )
        with self.transaction():
            applied = set()
            if (migrations_dir / "001_initial.sql").exists():
                applied.add("001_initial.sql")
            for path in sorted(migrations_dir.glob("*.sql")):
                if path.name in applied:
                    continue
                script = path.read_text(encoding="utf-8")
                for statement in _split_statements(script):
                    self._execute(statement)
                applied.add(path.name)

    def issue_enrollment_token(
        self,
        *,
        connector_id: str,
        capability_profile: str,
        display_label: str,
        expires_in_seconds: int,
        now: datetime | None = None,
    ) -> str:
        raw_token = secrets.token_urlsafe(32)
        current = now or utc_now()
        expires_at = current + timedelta(seconds=expires_in_seconds)
        self._execute(
            """
            INSERT INTO enrollment_tokens (
                token_hash, connector_id, capability_profile,
                display_label, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                hash_opaque(raw_token),
                connector_id,
                capability_profile,
                display_label,
                as_timestamp(expires_at),
                as_timestamp(current),
            ),
        )
        return raw_token

    def consume_enrollment_token(
        self,
        *,
        raw_token: str,
        connector_id: str,
        now: datetime,
    ) -> dict[str, Any] | None:
        token_hash = hash_opaque(raw_token)
        current = as_timestamp(now)
        with self.transaction():
            row = self._fetchone(
                """
                SELECT token_hash, connector_id, capability_profile,
                       display_label, expires_at, consumed_at
                FROM enrollment_tokens
                WHERE token_hash = ?
                """,
                (token_hash,),
            )
            if (
                row is None
                or row["consumed_at"] is not None
                or row["expires_at"] <= current
                or row["connector_id"] != connector_id
            ):
                return None
            self._execute(
                """
                UPDATE enrollment_tokens
                SET consumed_at = ?
                WHERE token_hash = ? AND consumed_at IS NULL
                """,
                (current, token_hash),
            )
            return row

    def create_challenge(
        self,
        *,
        expires_in_seconds: int = 120,
        now: datetime | None = None,
    ) -> dict[str, str]:
        challenge_id = str(uuid.uuid4())
        challenge = secrets.token_urlsafe(24)
        current = now or utc_now()
        self._execute(
            """
            INSERT INTO relay_challenges (
                challenge_id, challenge_hash, expires_at, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                challenge_id,
                hash_opaque(challenge),
                as_timestamp(current + timedelta(seconds=expires_in_seconds)),
                as_timestamp(current),
            ),
        )
        return {"challenge_id": challenge_id, "challenge": challenge}

    def consume_challenge(
        self,
        *,
        challenge_id: str,
        challenge: str,
        now: datetime,
    ) -> bool:
        current = as_timestamp(now)
        with self.transaction():
            row = self._fetchone(
                """
                SELECT challenge_hash, expires_at, consumed_at
                FROM relay_challenges
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            )
            if (
                row is None
                or row["consumed_at"] is not None
                or row["expires_at"] <= current
                or row["challenge_hash"] != hash_opaque(challenge)
            ):
                return False
            self._execute(
                """
                UPDATE relay_challenges
                SET consumed_at = ?
                WHERE challenge_id = ? AND consumed_at IS NULL
                """,
                (current, challenge_id),
            )
            return True

    def enroll_device(
        self,
        *,
        connector_id: str,
        public_key: str,
        display_label: str,
        capability_profile: str,
        now: datetime,
    ) -> bool:
        current = as_timestamp(now)
        capabilities = capabilities_for_profile(capability_profile)
        capabilities_json = json.dumps(
            list(capabilities),
            separators=(",", ":"),
            ensure_ascii=True,
        )
        with self.transaction():
            existing = self._fetchone(
                "SELECT connector_id FROM remote_agent_devices WHERE connector_id = ?",
                (connector_id,),
            )
            if existing is not None:
                return False
            self._execute(
                """
                INSERT INTO remote_agent_devices (
                    connector_id, public_key, display_label,
                    capability_profile, capabilities_json,
                    enrollment_state, enrolled_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'enrolled', ?, ?)
                """,
                (
                    connector_id,
                    public_key,
                    display_label,
                    capability_profile,
                    capabilities_json,
                    current,
                    current,
                ),
            )
            return True

    def get_device(self, connector_id: str) -> dict[str, Any] | None:
        return self._fetchone(
            """
            SELECT connector_id, public_key, display_label,
                   capability_profile, capabilities_json, enrollment_state,
                   enrolled_at, revoked_at, updated_at
            FROM remote_agent_devices
            WHERE connector_id = ?
            """,
            (connector_id,),
        )

    def list_devices(self) -> list[dict[str, Any]]:
        return self._fetchall(
            """
            SELECT connector_id, display_label, capability_profile,
                   capabilities_json, enrollment_state, enrolled_at,
                   revoked_at, updated_at
            FROM remote_agent_devices
            ORDER BY display_label, connector_id
            """
        )

    def revoke_device(
        self,
        *,
        connector_id: str,
        now: datetime,
    ) -> bool:
        current = as_timestamp(now)
        with self.transaction():
            row = self.get_device(connector_id)
            if row is None:
                return False
            self._execute(
                """
                UPDATE remote_agent_devices
                SET enrollment_state = 'revoked', revoked_at = ?,
                    updated_at = ?
                WHERE connector_id = ?
                """,
                (current, current, connector_id),
            )
            self._execute(
                """
                UPDATE live_instances
                SET state = 'offline', disconnected_at = ?
                WHERE connector_id = ? AND state != 'offline'
                """,
                (current, connector_id),
            )
            return True

    def delete_revoked_device(
        self,
        *,
        connector_id: str,
    ) -> str:
        with self.transaction():
            device = self.get_device(connector_id)
            if device is None:
                return "device_not_found"
            if device["enrollment_state"] != "revoked":
                return "device_not_revoked"
            self._execute(
                "DELETE FROM live_instances WHERE connector_id = ?",
                (connector_id,),
            )
            self._execute(
                "DELETE FROM remote_agent_devices WHERE connector_id = ?",
                (connector_id,),
            )
        return "deleted"

    def upsert_presence(
        self,
        *,
        connector_id: str,
        instance_id: str,
        connection_generation: str,
        context_epoch: int,
        capabilities: tuple[str, ...],
        now: datetime,
    ) -> bool:
        current = as_timestamp(now)
        capabilities_json = json.dumps(
            list(capabilities),
            separators=(",", ":"),
            ensure_ascii=True,
        )
        with self.transaction():
            device = self.get_device(connector_id)
            if device is None or device["enrollment_state"] != "enrolled":
                return False
            stored_capabilities = set(
                json.loads(device["capabilities_json"] or "[]")
            )
            if not set(capabilities).issubset(stored_capabilities):
                return False
            self._execute(
                """
                INSERT INTO live_instances (
                    instance_id, connector_id, connection_generation,
                    context_epoch, state, connected_at,
                    last_heartbeat_at
                ) VALUES (?, ?, ?, ?, 'online', ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    connector_id = excluded.connector_id,
                    connection_generation = excluded.connection_generation,
                    context_epoch = excluded.context_epoch,
                    state = 'online',
                    connected_at = excluded.connected_at,
                    last_heartbeat_at = excluded.last_heartbeat_at,
                    disconnected_at = NULL
                """,
                (
                    instance_id,
                    connector_id,
                    connection_generation,
                    context_epoch,
                    current,
                    current,
                ),
            )
            return True

    def heartbeat(
        self,
        *,
        instance_id: str,
        connection_generation: str,
        context_epoch: int,
        now: datetime,
    ) -> bool:
        current = as_timestamp(now)
        with self.transaction():
            row = self._fetchone(
                """
                SELECT connection_generation, context_epoch
                FROM live_instances
                WHERE instance_id = ? AND state = 'online'
                """,
                (instance_id,),
            )
            if (
                row is None
                or row["connection_generation"] != connection_generation
                or context_epoch < int(row["context_epoch"])
            ):
                return False
            self._execute(
                """
                UPDATE live_instances
                SET context_epoch = ?, last_heartbeat_at = ?
                WHERE instance_id = ? AND connection_generation = ?
                  AND state = 'online'
                """,
                (context_epoch, current, instance_id, connection_generation),
            )
            return True

    def disconnect_instance(
        self,
        *,
        instance_id: str,
        connection_generation: str,
        now: datetime,
    ) -> bool:
        current = as_timestamp(now)
        with self.transaction():
            row = self._fetchone(
                "SELECT connection_generation FROM live_instances WHERE instance_id = ?",
                (instance_id,),
            )
            if row is None or row["connection_generation"] != connection_generation:
                return False
            self._execute(
                """
                UPDATE live_instances
                SET state = 'offline', disconnected_at = ?
                WHERE instance_id = ? AND connection_generation = ?
                """,
                (current, instance_id, connection_generation),
            )
            return True

    def mark_stale_instances(
        self,
        *,
        stale_before: datetime,
    ) -> int:
        result = self._execute(
            """
            UPDATE live_instances
            SET state = 'offline'
            WHERE state = 'online' AND last_heartbeat_at <= ?
            """,
            (as_timestamp(stale_before),),
        )
        return result.rowcount

    def exact_online_instance(
        self,
        *,
        connector_id: str,
        instance_id: str,
    ) -> dict[str, Any] | None:
        return self._fetchone(
            """
            SELECT instance_id, connector_id, connection_generation,
                   context_epoch, state, connected_at, last_heartbeat_at
            FROM live_instances
            WHERE connector_id = ? AND instance_id = ? AND state = 'online'
            """,
            (connector_id, instance_id),
        )

    def latest_online_instance(
        self,
        *,
        connector_id: str,
    ) -> dict[str, Any] | None:
        return self._fetchone(
            """
            SELECT instance_id, connector_id, connection_generation,
                   context_epoch, state, connected_at, last_heartbeat_at
            FROM live_instances
            WHERE connector_id = ? AND state = 'online'
            ORDER BY last_heartbeat_at DESC
            LIMIT 1
            """,
            (connector_id,),
        )

    def claim_request(
        self,
        *,
        connector_id: str,
        idempotency_key: str,
        request_id: str,
        tool_name: str,
        request_digest: str,
        now: datetime,
    ) -> tuple[str, dict[str, Any] | None]:
        current = as_timestamp(now)
        self._execute(
            """
            INSERT OR IGNORE INTO agent_requests (
                connector_id, idempotency_key, request_id, tool_name,
                request_digest, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                connector_id,
                idempotency_key,
                request_id,
                tool_name,
                request_digest,
                current,
            ),
        )
        existing = self._fetchone(
            """
            SELECT request_id, request_digest, status, result_json
            FROM agent_requests
            WHERE connector_id = ? AND idempotency_key = ?
            """,
            (connector_id, idempotency_key),
        )
        if existing is None:
            raise RuntimeError("agent request claim was not persisted")
        if existing["request_id"] == request_id:
            return "new", None
        if existing["request_digest"] != request_digest:
            return "conflict", None
        if existing["status"] == "pending":
            return "pending", None
        return "replay", json.loads(existing["result_json"] or "{}")

    def complete_request(
        self,
        *,
        connector_id: str,
        idempotency_key: str,
        status: str,
        result: dict[str, Any],
        now: datetime,
    ) -> None:
        self._execute(
            """
            UPDATE agent_requests
            SET status = ?, result_json = ?, completed_at = ?
            WHERE connector_id = ? AND idempotency_key = ?
              AND status = 'pending'
            """,
            (
                status,
                json.dumps(
                    result,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ),
                as_timestamp(now),
                connector_id,
                idempotency_key,
            ),
        )

    def append_audit(
        self,
        *,
        action: str,
        result_code: str,
        agent_principal: str | None = None,
        connector_id: str | None = None,
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> str:
        event_id = str(uuid.uuid4())
        from .redaction import redact_audit_value

        self._execute(
            """
            INSERT INTO agent_audit_events (
                event_id, agent_principal, connector_id, request_id,
                action, result_code, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                agent_principal,
                connector_id,
                request_id,
                action,
                result_code,
                json.dumps(
                    redact_audit_value(details or {}),
                    separators=(",", ":"),
                    ensure_ascii=True,
                ),
                as_timestamp(now or utc_now()),
            ),
        )
        return event_id

    def audit_events(
        self,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 500))
        return self._fetchall(
            """
            SELECT event_id, agent_principal, connector_id, request_id,
                   action, result_code, details_json, created_at
            FROM agent_audit_events
            ORDER BY created_at DESC, event_id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        )


def _split_statements(script: str) -> list[str]:
    return [
        statement.strip()
        for statement in script.split(";")
        if statement.strip()
    ]
