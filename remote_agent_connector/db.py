from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence


class Database:
    """Small synchronous adapter for Postgres production and SQLite dev/tests."""

    def __init__(self, url: str):
        self.url = url
        self.is_sqlite = url.lower().startswith("sqlite:///")
        self._lock = threading.RLock()
        if self.is_sqlite:
            path = url[len("sqlite:///") :]
            if not path:
                raise RuntimeError("SQLite URL must include a database path")
            self._connection: Any = sqlite3.connect(
                path,
                check_same_thread=False,
                isolation_level=None,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
        else:
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL requires the postgres package extra: "
                    "pip install .[postgres]"
                ) from exc
            # Statement helpers below are intentionally usable outside an
            # explicit transaction. Autocommit makes their durable result
            # visible to the Hub/relay workers immediately, while
            # `connection.transaction()` still provides atomic blocks.
            self._connection = psycopg.connect(url, autocommit=True)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _sql(self, statement: str) -> str:
        return statement if self.is_sqlite else statement.replace("?", "%s")

    def execute(
        self,
        statement: str,
        parameters: Sequence[Any] = (),
    ) -> Any:
        with self._lock:
            if self.is_sqlite:
                return self._connection.execute(
                    self._sql(statement),
                    tuple(parameters),
                )
            with self._connection.cursor() as cursor:
                cursor.execute(self._sql(statement), tuple(parameters))
                return cursor

    def fetchone(
        self,
        statement: str,
        parameters: Sequence[Any] = (),
    ) -> dict[str, Any] | None:
        with self._lock:
            if self.is_sqlite:
                row = self._connection.execute(
                    self._sql(statement),
                    tuple(parameters),
                ).fetchone()
                return dict(row) if row is not None else None
            with self._connection.cursor() as cursor:
                cursor.execute(self._sql(statement), tuple(parameters))
                row = cursor.fetchone()
                if row is None:
                    return None
                return {
                    description.name: value
                    for description, value in zip(
                        cursor.description,
                        row,
                    )
                }

    def fetchall(
        self,
        statement: str,
        parameters: Sequence[Any] = (),
    ) -> list[dict[str, Any]]:
        with self._lock:
            if self.is_sqlite:
                rows = self._connection.execute(
                    self._sql(statement),
                    tuple(parameters),
                ).fetchall()
                return [dict(row) for row in rows]
            with self._connection.cursor() as cursor:
                cursor.execute(self._sql(statement), tuple(parameters))
                rows = cursor.fetchall()
                return [
                    {
                        description.name: value
                        for description, value in zip(
                            cursor.description,
                            row,
                        )
                    }
                    for row in rows
                ]

    @contextmanager
    def transaction(self) -> Iterator["Database"]:
        with self._lock:
            if self.is_sqlite:
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    yield self
                except Exception:
                    self._connection.execute("ROLLBACK")
                    raise
                else:
                    self._connection.execute("COMMIT")
            else:
                with self._connection.transaction():
                    yield self

    def migrate(self) -> None:
        migrations_dir = (
            Path(__file__).resolve().parent
            / "migrations"
            / ("sqlite" if self.is_sqlite else "postgres")
        )
        if not migrations_dir.is_dir():
            raise RuntimeError("Fleet Connector migration directory is missing")
        with self.transaction():
            self.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            applied = {
                row["version"]
                for row in self.fetchall(
                    "SELECT version FROM schema_migrations"
                )
            }
            for path in sorted(migrations_dir.glob("*.sql")):
                if path.name in applied:
                    continue
                for statement in _split_statements(
                    path.read_text(encoding="utf-8")
                ):
                    self.execute(statement)
                self.execute(
                    """
                    INSERT INTO schema_migrations(version, applied_at)
                    VALUES (?, CURRENT_TIMESTAMP)
                    """,
                    (path.name,),
                )


def _split_statements(script: str) -> list[str]:
    """Migrations use simple statements; preserve quoted semicolons."""
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    trigger_statement = False
    for char in script:
        current.append(char)
        if quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == ";":
            statement = "".join(current).strip()
            if not trigger_statement and statement.upper().startswith(
                "CREATE TRIGGER"
            ):
                trigger_statement = True
            if trigger_statement and not statement.upper().endswith("END;"):
                continue
            if statement:
                statements.append(statement)
            current = []
            trigger_statement = False
    trailing = "".join(current).strip()
    if trailing:
        statements.append(trailing)
    return statements
