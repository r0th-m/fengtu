# 丰图 server 一体化镜像(M5 主部署形态,DESIGN §12)。
# 三阶段:前端构建 → Go 构建(go:embed 要求 dist 先就位) → 运行时。
# 产物:单二进制 + configs/ 全套 + curl(健康检查),数据目录 /app/data 挂卷。
#
# 构建:
#   docker compose build            # 推荐(走根 compose)
#   国内加速:docker compose build --build-arg NPM_REGISTRY=https://registry.npmmirror.com
#   (Go 依赖走 vendor/ 全量内嵌,构建期零外网拉取)

# ---- 阶段一:前端构建(vite outDir 直指 internal/webui/dist) ----
FROM node:20-bookworm-slim AS webbuild
ARG NPM_REGISTRY=
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN if [ -n "$NPM_REGISTRY" ]; then npm config set registry "$NPM_REGISTRY"; fi \
 && npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 阶段二:Go 构建(vendor 模式,不拉外网;dist 必须先从阶段一拷入) ----
FROM golang:1.26-bookworm AS gobuild
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/
# 前端产物覆盖占位 dist(go:embed all:dist 吃进二进制)
COPY --from=webbuild /src/internal/webui/dist internal/webui/dist
RUN CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -trimpath -ldflags="-s -w" \
    -o /out/fengtu ./cmd/fengtu

# ---- 阶段三:运行时(debian-slim;curl 供健康检查,ca-certificates 供 AI 外发 TLS) ----
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --home-dir /app --shell /usr/sbin/nologin fengtu
WORKDIR /app
COPY --from=gobuild /out/fengtu /app/fengtu
COPY configs/ /app/configs/
RUN mkdir -p /app/data && chown -R fengtu:fengtu /app/data
USER fengtu
# 容器内必须绑 0.0.0.0(宿主侧绑定纪律由 compose 端口映射收口,
# 缺省只露 127.0.0.1:8200);缺省 configs 相对路径以 /app 为工作目录。
ENV FENGTU_LISTEN=0.0.0.0:8200 \
    FENGTU_DATA_DIR=/app/data
EXPOSE 8200
ENTRYPOINT ["/app/fengtu"]
