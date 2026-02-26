FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY aip_mcp_server/ aip_mcp_server/

RUN pip install --no-cache-dir .

EXPOSE 8080

ENTRYPOINT ["aip-mcp-server"]
