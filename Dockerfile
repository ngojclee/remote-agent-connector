FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY pyproject.toml README.md ./
COPY remote_agent_connector ./remote_agent_connector

RUN python -m pip install --no-cache-dir ".[postgres]"

USER 10001:10001

EXPOSE 3030

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3030/health', timeout=3).read()"]

ENTRYPOINT ["remote-agent-connector"]
