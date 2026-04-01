# syntax=docker/dockerfile:1

FROM node:lts-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
    age \
    libatomic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN addgroup --system --gid 10001 appuser && \
    adduser --system --uid 10001 --gid 10001 --home /home/appuser --shell /bin/false appuser

FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tar \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then PLAT="linux_amd64"; \
    elif [ "$ARCH" = "arm64" ]; then PLAT="linux_arm64"; \
    else PLAT="linux_386"; fi && \
    curl -LO "https://github.com/ipinfo/mmdbctl/releases/download/mmdbctl-1.4.9/mmdbctl_1.4.9_${PLAT}.tar.gz" && \
    mkdir -p ./mmdb-temp && \
    tar -xzf "mmdbctl_1.4.9_${PLAT}.tar.gz" -C ./mmdb-temp && \
    find ./mmdb-temp -type f -name "mmdbctl*" -exec mv {} /usr/local/bin/mmdbctl \; && \
    chmod +x /usr/local/bin/mmdbctl && \
    rm -rf "mmdbctl_1.4.9_${PLAT}.tar.gz" ./mmdb-temp


COPY package*.json ./
RUN npm ci
RUN npx @riavzon/bot-detector init --contact="Riavzon - contact@riavzon.com"

COPY . .
RUN npm run build

FROM base AS production

RUN mkdir -p /app/auth-logs && \
    chown -R appuser:appuser /app/auth-logs

RUN mkdir -p /app/bot-detector-logs && \
    chown -R appuser:appuser /app/bot-detector-logs

COPY decrypt.sh .
COPY healthcheck.js .
COPY config.json.age .


RUN chmod +x decrypt.sh && \
    chown appuser:appuser decrypt.sh healthcheck.js

COPY --from=builder /usr/local/bin/mmdbctl /usr/local/bin/mmdbctl
RUN chmod +x /usr/local/bin/mmdbctl

COPY --from=builder --chown=appuser:appuser /app/package.json ./package.json
COPY --from=builder --chown=appuser:appuser /app/package-lock.json ./package-lock.json
COPY --from=builder --chown=appuser:appuser /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appuser /app/dist ./dist
ENV NODE_ENV=production

USER appuser

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["node", "healthcheck.js"]

ENTRYPOINT ["./decrypt.sh"]
CMD ["node", "dist/service.mjs"] 