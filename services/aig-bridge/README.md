# AIG Bridge Service

Python/FastAPI sidecar that bridges **Singularity AIDR** with **Tencent AI-Infra-Guard (AIG)**.

## What it does

The bridge translates AIDR's synchronous-style scan requests into AIG's internal async task workflow.
It provides a clean REST API for AIDR's core to consume, while AIG handles the actual scanning.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check + AIG connectivity status |
| `POST` | `/api/v1/scan/infra` | Submit AI infrastructure CVE scan |
| `GET` | `/api/v1/scan/infra/{task_id}` | Poll infra scan results |
| `POST` | `/api/v1/scan/mcp` | Submit MCP server security scan |
| `GET` | `/api/v1/scan/mcp/{task_id}` | Poll MCP scan results |
| `POST` | `/api/v1/scan/agent` | Submit Agent-Scan workflow |
| `POST` | `/api/v1/evaluate/jailbreak` | Submit jailbreak evaluation |
| `GET` | `/api/v1/threats/latest` | Get latest threat intelligence for AIDR sync |

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run with hot-reload
uvicorn app.main:app --reload --port 8099

# Set AIG server URL (if running AIG separately)
export BRIDGE_AIG_URL=http://localhost:8088

# Run tests
pytest
```

## Docker

```bash
# Build
docker build -t aig-bridge .

# Run
docker run -p 8099:8099 \
  -e BRIDGE_AIG_URL=http://aig-server:8088 \
  aig-bridge
```

## Architecture

See [`docs/architecture/aig-integration.md`](../../docs/architecture/aig-integration.md) for the full integration architecture.

## Attribution

This integration uses AI-Infra-Guard by Tencent Zhuque Lab (Apache 2.0).
See `vendor/ai-infra-guard/NOTICE` for attribution requirements.
