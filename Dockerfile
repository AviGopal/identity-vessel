# syntax=docker/dockerfile:1
# Build arguments for version embedding
ARG BUILD_SHA
ARG BUILD_VERSION

FROM oven/bun:1.2 AS build
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY src ./src
COPY tsconfig.json ./

FROM oven/bun:1.2-slim AS runtime
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/src ./src
COPY --from=build /app/package.json ./
# Re-declare build args
ARG BUILD_SHA
ARG BUILD_VERSION

ENV NODE_ENV=production
ENV BUILD_SHA=${BUILD_SHA}
ENV BUILD_VERSION=${BUILD_VERSION}
USER bun
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD bun -e "fetch('http://localhost:8080/health').then(r => process.exit(r.ok ? 0 : 1))"
CMD ["bun", "run", "src/index.ts"]
