from __future__ import annotations

import uvicorn

from .config import RemoteAgentConfig
from .server import create_app


def main() -> None:
    config = RemoteAgentConfig.from_env()
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.bind_port,
        log_level="info",
    )
