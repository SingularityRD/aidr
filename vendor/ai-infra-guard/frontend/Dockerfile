# =============================================================================
# 开源版 Dockerfile（多阶段构建：node 打包 -> nginx 服务）
# =============================================================================

# ---- Stage 1: Build ----
FROM node:18-alpine@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e AS builder

WORKDIR /app

# 安装 pnpm
RUN npm install -g pnpm@9.15.9

# 依赖缓存友好
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# 复制源码并构建
COPY . .
RUN rm -rf node_modules/.vite-temp dist \
    && pnpm exec tsc -b \
    && pnpm exec vite build --mode openSource

# ---- Stage 2: Serve ----
FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# 使用默认 nginx 配置模板；如需 SPA 路由 fallback，可挂载自定义 nginx.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# SPA fallback 到 index.html
RUN printf 'server {\n\
  listen 80;\n\
  root /usr/share/nginx/html;\n\
  index index.html;\n\
  location / {\n\
    try_files $uri $uri/ /index.html;\n\
  }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
