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
    git \
    openssh-client \
    ca-certificates \
    python3 \
    make \
    g++


COPY package*.json ./
RUN --mount=type=ssh,uid=10001,gid=10001 \
        npm install --foreground-scripts --ignore-scripts=false
        
COPY . .
RUN npm run build:prod

FROM base AS production

RUN mkdir -p /app/logs && \
    chown appuser:appuser /app/logs
    
COPY decrypt.sh .
COPY healthcheck.js .
COPY config.json.age .


RUN chmod +x decrypt.sh && \
    chown appuser:appuser decrypt.sh healthcheck.js

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
CMD ["node", "dist/service.js"] 