# syntax=docker/dockerfile:1.7
#
# SingRayPanel 镜像 —— 单 Dockerfile 双目标:
#   --target server  API 进程 (Node, 非 root)
#   --target web     nginx 托管 Vite 产物并反代 /api /sub
#
# 选 node:24-alpine 的原因: 项目只用 node:sqlite(内置)、bcryptjs、ssh2,
# 全部无需编译原生模块, alpine 完全够用。若将来引入原生依赖再换 -slim。

ARG NODE_VERSION=24

# ---------------------------------------------------------------- 依赖 + 构建
# 钉在 BUILDPLATFORM: tsc/vite 的产物是架构无关的 JS, 让它们在 runner 原生架构上跑,
# arm64 镜像就不必把整个构建过程放进 QEMU 模拟(多架构构建提速数倍)。
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine AS builder

# ssh2 的 optional 依赖(cpu-features)会尝试 node-gyp, 装上构建工具避免噪音;
# 构建失败也只是退回纯 JS 实现, 不影响功能。
RUN apk add --no-cache python3 make g++ ca-certificates

WORKDIR /app

# 先只拷贝 workspace 清单, 让依赖层独立缓存(改业务代码不重装依赖)
COPY package.json package-lock.json ./
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY tools/migrate/package.json tools/migrate/
RUN npm ci --no-audit --no-fund

COPY . .

# 根 build = shared(tsc) → server(tsc) → web(tsc --noEmit && vite build)
RUN npm run build

# ------------------------------------------------------------ 生产依赖(瘦身)
FROM node:${NODE_VERSION}-alpine AS prod-deps

WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
COPY packages/shared/package.json packages/shared/
COPY tools/migrate/package.json tools/migrate/
# --ignore-scripts: 生产运行时不需要安装脚本, 也避免任何 build 步骤
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# ------------------------------------------------------------- 运行时: API
FROM node:${NODE_VERSION}-alpine AS server

# tzdata: 备份小时数(backupHour)按进程本地时间判断, 容器默认 UTC 会让
# "凌晨 4 点备份"变成北京时间中午 12 点。
RUN apk add --no-cache tzdata

ENV NODE_ENV=production \
    TZ=Asia/Shanghai \
    PANEL_HOST=0.0.0.0 \
    PANEL_PORT=3000 \
    PANEL_DB=/app/data/panel.db \
    PANEL_BACKUP_DIR=/app/data/backups

WORKDIR /app

RUN addgroup -S panel && adduser -S -G panel panel

COPY --from=prod-deps --chown=panel:panel /app/node_modules        ./node_modules
COPY --from=builder   --chown=panel:panel /app/package.json        ./package.json
COPY --from=builder   --chown=panel:panel /app/packages/shared/package.json ./packages/shared/package.json
COPY --from=builder   --chown=panel:panel /app/packages/shared/dist         ./packages/shared/dist
COPY --from=builder   --chown=panel:panel /app/apps/server/package.json     ./apps/server/package.json
COPY --from=builder   --chown=panel:panel /app/apps/server/dist             ./apps/server/dist

# SQLite + 每日备份都落在这里, 必须挂卷
RUN mkdir -p /app/data/backups && chown -R panel:panel /app/data

USER panel
EXPOSE 3000

# 内置 /health 已就绪, 直接复用, 不额外装 curl
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PANEL_PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# 注意: index.ts 用 isMain 判断, 必须直接 node 启动, 不要包一层 shell
CMD ["node", "apps/server/dist/index.js"]

# ------------------------------------------------------------- 运行时: Web
FROM nginx:1.27-alpine AS web

COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/apps/web/dist /usr/share/nginx/html

EXPOSE 80
