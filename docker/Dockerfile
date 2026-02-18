FROM oven/bun:1.2-alpine AS base
WORKDIR /app

# Install security updates and tini
RUN apk update && apk upgrade && \
    apk add --no-cache tini && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S clawshield && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G clawshield -g clawshield clawshield

# Dependencies stage
FROM base AS deps
COPY package.json bun.lock ./
RUN HUSKY=0 bun install --frozen-lockfile --production

# Build stage
FROM base AS build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN bun run build

# Production stage
FROM base AS production

COPY --from=build --chown=clawshield:clawshield /app/dist ./dist
COPY --from=deps --chown=clawshield:clawshield /app/node_modules ./node_modules
COPY --chown=clawshield:clawshield package.json ./

USER clawshield

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]

EXPOSE 3000

CMD ["bun", "run", "dist/index.js"]
