"""The CI runtime classifier must never swallow a real code change.

Publishing ``:latest`` or ``:relay-latest`` makes Watchtower restart the
connector or the relay, and a relay restart drops live device connections. The
classifier therefore decides when a commit is allowed to do that, and it must
fail toward publishing whenever it cannot explain a change.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "ci_runtime_paths.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "ra_ci_runtime_paths", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


classifier = _load()


class RuntimePathClassificationTests(unittest.TestCase):
    def test_non_runtime_paths_do_not_publish(self):
        for path in (
            "README",
            "tests/test_signed_app_assertion.py",
            "tests/fixtures/app_assertion_vector.json",
            ".github/workflows/publish-ghcr.yml",
            "scripts/ci_runtime_paths.py",
            "docs/plan.md",
        ):
            with self.subTest(path=path):
                self.assertFalse(classifier.is_runtime_path(path))

    def test_runtime_paths_publish(self):
        for path in (
            "remote_agent_connector/service.py",
            "remote_agent_connector/migrations/sqlite/001_initial.sql",
            "deploy/Dockerfile.relay",
            "deploy/remote-agent-relay.nginx.conf",
            "pyproject.toml",
            "README.md",
            "Dockerfile",
        ):
            with self.subTest(path=path):
                self.assertTrue(classifier.is_runtime_path(path))

    def test_unrecognised_input_fails_toward_publishing(self):
        for path in ("", "   ", "/", "./", "remote_agent_connector"):
            with self.subTest(path=path):
                self.assertTrue(classifier.is_runtime_path(path))

    def test_mixed_commit_is_classified_runtime(self):
        runtime, hits = classifier.classify(
            [
                "tests/test_mcp_endpoint.py",
                "remote_agent_connector/relay.py",
            ]
        )
        self.assertTrue(runtime)
        self.assertEqual(hits, ["remote_agent_connector/relay.py"])

    def test_test_and_fixture_only_commit_is_not_runtime(self):
        runtime, hits = classifier.classify(
            [
                "tests/test_signed_app_assertion.py",
                "tests/fixtures/app_assertion_vector.json",
            ]
        )
        self.assertFalse(runtime)
        self.assertEqual(hits, [])

    def test_missing_base_range_fails_toward_publishing(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            classifier.main(
                ["--base", classifier.ZERO_SHA, "--head", "abc"]
            )
        self.assertIn("runtime=true", buffer.getvalue())
        self.assertIn("reason=base-unknown", buffer.getvalue())

    def test_unusable_git_range_fails_toward_publishing(self):
        buffer = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(
            errors
        ):
            classifier.main(
                ["--base", "deadbeefdeadbeef", "--head", "cafebabecafebabe"]
            )
        self.assertIn("runtime=true", buffer.getvalue())
        self.assertIn("reason=diff-failed", buffer.getvalue())

    def test_dotfiles_keep_their_leading_dot(self):
        """A naive lstrip("./") turned .dockerignore into dockerignore."""
        for path in (".dockerignore", "./.dockerignore", "/.dockerignore"):
            with self.subTest(path=path):
                self.assertTrue(classifier.is_runtime_path(path))
        for path in (".env.example", "./.github"):
            with self.subTest(path=path):
                self.assertFalse(classifier.is_runtime_path(path))


class DockerfileAgreementTests(unittest.TestCase):
    """Both published images must be covered by the classifier."""

    def _copy_sources(self, dockerfile: Path) -> list[str]:
        sources = []
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("COPY "):
                sources.extend(stripped.split()[1:-1])
        return sources

    def test_connector_image_sources_are_runtime(self):
        sources = self._copy_sources(REPO_ROOT / "Dockerfile")
        self.assertTrue(sources)
        for source in sources:
            candidate = source.rstrip("/")
            if (REPO_ROOT / candidate).is_dir():
                candidate += "/"
            with self.subTest(source=source):
                self.assertTrue(classifier.is_runtime_path(candidate))

    def test_relay_image_sources_are_runtime(self):
        relay_root = REPO_ROOT / "deploy"
        sources = self._copy_sources(relay_root / "Dockerfile.relay")
        self.assertTrue(sources)
        for source in sources:
            candidate = source.lstrip("./")
            if not candidate.startswith("deploy/"):
                candidate = "deploy/" + candidate
            with self.subTest(source=source):
                self.assertTrue(classifier.is_runtime_path(candidate))


if __name__ == "__main__":
    unittest.main()
