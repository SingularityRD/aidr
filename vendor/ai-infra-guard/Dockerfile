# 多阶段构建Dockerfile
# 第一阶段：构建前端
FROM node:22-alpine@sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85 AS frontend-builder

# 安装pnpm
RUN corepack enable && corepack prepare pnpm@10.8.1 --activate

WORKDIR /app/frontend

# 先复制依赖文件以利用缓存
COPY frontend/package.json frontend/pnpm-lock.yaml ./

# 安装依赖
RUN pnpm install --frozen-lockfile --ignore-scripts

# 复制前端源代码
COPY frontend/ .

# 构建前端
RUN rm -rf node_modules/.vite-temp dist \
    && pnpm exec tsc -b \
    && pnpm exec vite build --mode openSource

# 第二阶段：构建Go应用
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git ca-certificates tzdata

# 复制源代码（包含go.mod和go.sum）
COPY . .

# 清空旧的static文件并复制前端构建产物
RUN rm -rf ./common/websocket/static/*
COPY --from=frontend-builder /app/frontend/dist/ ./common/websocket/static/

# 下载依赖
RUN go mod download

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -buildvcs=false -o ai-infra-guard ./cmd/cli/main.go

# 第二阶段：运行阶段（使用Python 3.12 Alpine镜像）
FROM python:3.12-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111

# 安装运行时依赖
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    bash \
    curl \
    git

# Install the resolver from a checked-in hash lock as well; an exact version
# alone does not authenticate the downloaded wheel.
COPY uv-bootstrap.lock /tmp/uv-bootstrap.lock
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        -r /tmp/uv-bootstrap.lock \
    && rm /tmp/uv-bootstrap.lock

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件和配置文件
COPY --from=builder /app/ai-infra-guard .
COPY --from=builder /app/trpc_go.yaml .
COPY --from=builder /app/CHANGELOG.md .

# 复制数据文件到容器中
COPY --from=builder /app/data ./data

# 复制agent-scan目录并使用uv安装Python依赖
COPY ./agent-scan /app/agent-scan
RUN cd /app/agent-scan \
    && /usr/local/bin/uv sync --frozen --no-dev

# 复制启动脚本到镜像中
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh && chown root:root /app/start.sh

# 创建必要的目录并设置权限（仅对镜像内有效）
RUN mkdir -p /app/uploads \
    /app/db \
    /app/logs && \
    addgroup -g 1000 -S aig && \
    adduser -S -D -H -u 1000 -G aig aig && \
    chown -R aig:aig /app && \
    chmod -R 755 /app && \
    mkdir -p /app/AIG-PromptSecurity/utils
COPY ./AIG-PromptSecurity/utils/strategy_map.json /app/AIG-PromptSecurity/utils/strategy_map.json

# 设置环境变量
ENV APP_ENV=production
ENV UPLOAD_DIR=/app/uploads
ENV DB_PATH=/app/db/tasks.db
ENV TZ=Asia/Shanghai
ENV PYTHONUNBUFFERED=1
ENV AIG_API_CHECKER_URL=http://agent:8000

# 暴露端口
EXPOSE 8088

USER aig

# 声明卷挂载点
VOLUME ["/app/uploads", "/app/db", "/app/logs"]

# The UI and process can be alive while the signed scan dataset is unusable.
# Probe the authenticated runtime-evidence endpoint so standalone use is also
# fail-closed. Compose overrides this with the equivalent explicit probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS -H "X-AIG-Agent-Token: ${AIG_AGENT_SHARED_SECRET}" \
        http://127.0.0.1:8088/api/v1/internal/readiness || exit 1

# 启动命令
CMD ["/app/start.sh"]
