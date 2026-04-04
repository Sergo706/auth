# syntax=docker/dockerfile:1

FROM golang:bookworm AS go-builder
RUN go install filippo.io/age/cmd/...@latest && \
    go install github.com/ipinfo/mmdbctl@latest


FROM node:lts-slim AS base
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libatomic1 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN addgroup --system --gid 10001 appuser && \
    adduser --system --uid 10001 --gid 10001 --home /home/appuser --shell /bin/false appuser

FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci
COPY --from=go-builder /go/bin/mmdbctl /usr/local/bin/mmdbctl
RUN ./node_modules/.bin/bot-detector init --contact="Riavzon - contact@riavzon.com"

COPY . .
RUN npm run build

FROM base AS production

RUN mkdir -p /app/auth-logs /app/bot-detector-logs && \
    chown -R appuser:appuser /app/auth-logs /app/bot-detector-logs

COPY decrypt.sh healthcheck.js ./

RUN chmod +x decrypt.sh && \
    chown appuser:appuser decrypt.sh healthcheck.js

COPY --from=go-builder /go/bin/age /usr/local/bin/age
COPY --from=go-builder /go/bin/age-keygen /usr/local/bin/age-keygen
COPY --from=go-builder /go/bin/mmdbctl /usr/local/bin/mmdbctl
RUN chmod +x /usr/local/bin/mmdbctl /usr/local/bin/age /usr/local/bin/age-keygen

COPY --from=builder --chown=appuser:appuser /app/package.json ./package.json
COPY --from=builder --chown=appuser:appuser /app/package-lock.json ./package-lock.json
COPY --from=builder --chown=appuser:appuser /app/dist ./dist

RUN npm ci --omit=dev --ignore-scripts && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/yarn* /usr/local/bin/corepack /opt/yarn* && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt /var/log/* /tmp/* /root/.npm
COPY --from=builder --chown=appuser:appuser /app/node_modules/@riavzon/bot-detector/dist/_data-sources ./node_modules/@riavzon/bot-detector/dist/_data-sources

ENV NODE_ENV=production

USER appuser

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["node", "healthcheck.js"]

ENTRYPOINT ["./decrypt.sh"]
CMD ["node", "dist/service.mjs"] 