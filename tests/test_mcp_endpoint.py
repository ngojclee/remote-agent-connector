from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from remote_agent_connector.config import RemoteAgentConfig
from remote_agent_connector.server import create_app
from remote_agent_connector.store import RemoteAgentStore


class RemoteAgentEndpointTests(unittest.TestCase):
    def test_mcp_catalog_is_typed_and_closed(self):
        temp_dir = tempfile.TemporaryDirectory()
        try:
            config = RemoteAgentConfig(
                database_url=f"sqlite:///{Path(temp_dir.name) / 'remote-agent.sqlite'}",
                mcp_bearer_token="m" * 48,
                hub_delegation_secret="d" * 48,
                operator_bearer_token="o" * 48,
                hub_audience="remote-agent-connector",
                private_mcp_url="http://127.0.0.1:3030/mcp",
                bind_host="127.0.0.1",
                bind_port=3030,
                allowed_hosts=("127.0.0.1:3030", "localhost:3030"),
                allow_insecure_private_mcp=True,
                trust_proxy_tls=False,
                request_timeout_seconds=2,
                heartbeat_timeout_seconds=2,
            )
            store = RemoteAgentStore(config.database_url)
            app = create_app(config, store)
            tools = asyncio.run(app.state.mcp_server.list_tools())
            self.assertEqual(
                {tool.name for tool in tools},
                {
                    "connector_health",
                    "files_list",
                    "files_stat",
                    "files_search",
                    "files_read",
                    "files_write",
                    "files_delete",
                    "files_move",
                    "files_mkdir",
                    "files_upload",
                    "files_download",
                    "terminal_execute",
                    "terminal_stream",
                    "ssh_execute",
                    "ssh_list_profiles",
                    "skills_list",
                    "skills_materialize",
                    "skills_execute",
                    "mcp_list_servers",
                    "mcp_call",
                    "mcp_health",
                    "skills_health",
                    "connector_restart_mcp",
                },
            )
        finally:
            store.close()
            temp_dir.cleanup()
