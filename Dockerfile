FROM oven/bun:1.3.11 AS base
WORKDIR /app

# Install dependencies
FROM base AS install
COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile --production

# Build stage
FROM base AS build
COPY --from=install /app/node_modules ./node_modules
COPY . .

# Type check (fails build if types are wrong)
RUN bun run typecheck

# Run tests (fails build if tests fail)
RUN bun test

# Production stage
FROM base AS release
COPY --from=install /app/node_modules ./node_modules
COPY --from=build /app/src ./src
COPY --from=build /app/package.json ./
COPY --from=build /app/tsconfig.json ./

# Create non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 bunuser
USER bunuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD bun -e "const res = await fetch('http://localhost:8080/health'); process.exit(res.ok ? 0 : 1)"

# Start server
CMD ["bun", "run", "src/index.ts"]
