# AgentProof Dockerfile
FROM node:20-alpine AS base
WORKDIR /app

# Install build dependencies for native modules (better-sqlite3)
RUN apk add --no-cache python3 make g++ 

# Install dependencies
FROM base AS deps
COPY package.json package-lock.json ./
RUN npm ci

# Build
FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# Production
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV DATABASE_PATH=/app/data/agentproof.db

# Install runtime dependencies for better-sqlite3
RUN apk add --no-cache libstdc++

# Create data directory
RUN mkdir -p /app/data

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules

# Create non-root user
RUN addgroup --system --gid 1001 agentproof && \
    adduser --system --uid 1001 agentproof && \
    chown -R agentproof:agentproof /app
USER agentproof

EXPOSE 3000

CMD ["node", "--experimental-specifier-resolution=node", "dist/index.js"]
