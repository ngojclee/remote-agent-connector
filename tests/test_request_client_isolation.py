"""Idempotency must be per caller, not per device.

The old primary key was (connector_id, idempotency_key) with no caller column,
so a replay arriving under a different client_id was served another caller's
stored result. Idempotency protects one caller against its own transport retry,
and a different caller is not the same logical operation. These tests pin the
new key and pin that the migration carries every existing row forward.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from remote_agent_connector.store import RemoteAgentStore
from remote_agent_connector.protocol import ProtocolError, parse_client_id

MIGRATIONS = (
    Path(__file__).resolve().parents[1]
    / "remote_agent_connector"
    / "migrations"
    / "sqlite"
)
CONNECTOR = "agy2api-10.11.1.1"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class RequestClientIsolationTests(unittest.TestCase):
    def _store(self, temp_dir: str) -> RemoteAgentStore:
        return RemoteAgentStore(f"sqlite:///{Path(temp_dir) / 'requests.sqlite'}")

    def _claim(self, store, *, client_id, key, digest="digest-a"):
        return store.claim_request(
            connector_id=CONNECTOR,
            client_id=client_id,
            idempotency_key=key,
            request_id=str(uuid.uuid4()),
            tool_name="files.write",
            request_digest=digest,
            now=_now(),
        )

    def test_two_callers_sharing_a_key_do_not_collide(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = self._store(temp_dir)
            try:
                key = "shared-key-0001"
                first, _ = self._claim(store, client_id="agy2api", key=key)
                second, _ = self._claim(store, client_id="codex-10-11-1-1", key=key)
                self.assertEqual(first, "new")
                self.assertEqual(second, "new")
            finally:
                store.close()

    def test_same_caller_retrying_its_own_key_still_replays(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = self._store(temp_dir)
            try:
                key = "retry-key-0001"
                outcome, _ = self._claim(store, client_id="agy2api", key=key)
                self.assertEqual(outcome, "new")
                store.complete_request(
                    connector_id=CONNECTOR,
                    client_id="agy2api",
                    idempotency_key=key,
                    status="completed",
                    result={"code": "ok", "written": True},
                    now=_now(),
                )
                outcome, replay = self._claim(store, client_id="agy2api", key=key)
                self.assertEqual(outcome, "replay")
                self.assertEqual(replay.get("code"), "ok")
            finally:
                store.close()

    def test_same_caller_same_key_different_arguments_is_a_conflict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = self._store(temp_dir)
            try:
                key = "conflict-key-0001"
                self._claim(store, client_id="agy2api", key=key, digest="digest-a")
                outcome, _ = self._claim(
                    store, client_id="agy2api", key=key, digest="digest-b"
                )
                self.assertEqual(outcome, "conflict")
            finally:
                store.close()

    def test_completing_one_caller_does_not_settle_another(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = self._store(temp_dir)
            try:
                key = "cross-complete-0001"
                self._claim(store, client_id="agy2api", key=key)
                self._claim(store, client_id="hermes", key=key)
                store.complete_request(
                    connector_id=CONNECTOR,
                    client_id="agy2api",
                    idempotency_key=key,
                    status="completed",
                    result={"code": "ok"},
                    now=_now(),
                )
                rows = store._connection.execute(
                    "SELECT client_id, status FROM agent_requests "
                    "WHERE connector_id = ? AND idempotency_key = ? "
                    "ORDER BY client_id",
                    (CONNECTOR, key),
                ).fetchall()
                self.assertEqual(
                    {row[0]: row[1] for row in rows},
                    {"agy2api": "completed", "hermes": "pending"},
                )
            finally:
                store.close()

    def test_the_empty_sentinel_is_unreachable_by_construction(self):
        """A tombstone is not a caller.

        Rows backfilled to an empty client_id stay in the table as history. They
        must never be claimable, replayed or completed by a live caller, so the
        parser that gates every inbound client id has to refuse the empty string.
        """
        with self.assertRaises(ProtocolError):
            parse_client_id("")
        with self.assertRaises(ProtocolError):
            parse_client_id("   ")


class MigrationPreservationTests(unittest.TestCase):
    def test_existing_rows_survive_and_are_backfilled_from_audit(self):
        temp_dir = tempfile.mkdtemp()
        try:
            database_path = Path(temp_dir) / "legacy.sqlite"
            connection = sqlite3.connect(database_path)
            connection.executescript(
                (MIGRATIONS / "001_initial.sql").read_text(encoding="utf-8")
            )
            # The real legacy state is 001 with no schema_migrations rows, which
            # is the only shape the store bootstraps. 002 and 003 then run.
            attributable = str(uuid.uuid4())
            anonymous = str(uuid.uuid4())
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for request_id, key in ((attributable, "k-attr"), (anonymous, "k-anon")):
                connection.execute(
                    "INSERT INTO agent_requests (connector_id, idempotency_key, "
                    "request_id, tool_name, request_digest, status, result_json, "
                    "created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        CONNECTOR,
                        key,
                        request_id,
                        "files.write",
                        "digest",
                        "completed",
                        '{"code":"ok"}',
                        stamp,
                        stamp,
                    ),
                )
            connection.execute(
                "INSERT INTO agent_audit_events (event_id, agent_principal, "
                "connector_id, request_id, action, result_code, details_json, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    "agy2api",
                    CONNECTOR,
                    attributable,
                    "mcp.files.write",
                    "ok",
                    "{}",
                    stamp,
                ),
            )
            connection.commit()
            before = connection.execute(
                "SELECT COUNT(*) FROM agent_requests"
            ).fetchone()[0]
            connection.close()

            store = RemoteAgentStore(f"sqlite:///{database_path}")
            try:
                rows = store._connection.execute(
                    "SELECT request_id, client_id, idempotency_key, status "
                    "FROM agent_requests"
                ).fetchall()
                after = {row[0]: row for row in rows}
                # Nothing is dropped and nothing is left unreachable.
                self.assertEqual(len(rows), before)
                self.assertEqual(after[attributable][1], "agy2api")
                # An unattributable row keeps a value no live client can have.
                self.assertEqual(after[anonymous][1], "")
                self.assertEqual({row[2] for row in rows}, {"k-attr", "k-anon"})
                self.assertTrue(
                    all(row[3] == "completed" for row in rows)
                )
            finally:
                store.close()
        finally:
            # Windows can hold the sqlite handle briefly after close, and the
            # assertions above are the point of the test, not the cleanup.
            import shutil

            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
