# Posture scanner agent image for the AIDR Helm chart: the upstream agent image
# built from vendor/ai-infra-guard/Dockerfile_Agent plus the tracked MCP SDK
# import shim (services/aig-bridge/aig_compat) that
# docker-compose.posture-scanner.yml bind-mounts. The base is built in the same
# run (build-images.mjs) from a digest-pinned Dockerfile_Agent, so it is passed
# as a build argument; USER restates the base image's non-root user.
ARG AIG_AGENT_BASE
FROM ${AIG_AGENT_BASE}
COPY aig_compat /app/aig-compat
ENV PYTHONPATH=/app/aig-compat
USER agent
