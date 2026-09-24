# AIG agent image for the AIDR Helm chart: the upstream agent image built from
# vendor/ai-infra-guard/Dockerfile_Agent plus the tracked MCP SDK import shim
# (services/aig-bridge/aig_compat) that docker-compose.aig.yml bind-mounts.
ARG AIG_AGENT_BASE
FROM ${AIG_AGENT_BASE}
COPY aig_compat /app/aig-compat
ENV PYTHONPATH=/app/aig-compat
