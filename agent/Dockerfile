# AgentCore Runtime runs arm64 containers that listen on 8080 (/invocations, /ping).
FROM --platform=linux/arm64 ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY writ_agent ./writ_agent
RUN uv sync --frozen --no-dev

RUN useradd --uid 1000 --no-create-home agent
USER agent
EXPOSE 8080
CMD ["/app/.venv/bin/python", "-m", "writ_agent.app"]
