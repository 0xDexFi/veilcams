# ─── Builder Stage ───────────────────────────────────────────────
FROM node:22-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json ./
COPY src/ ./src/
COPY configs/ ./configs/

RUN npm run build

# ─── Runtime Stage ───────────────────────────────────────────────
FROM node:22-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    dnsutils \
    net-tools \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 -s /bin/bash veilcams

WORKDIR /app

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./
COPY --from=builder /app/configs ./configs
COPY --from=builder /app/tsconfig.json ./

# Create required directories
RUN mkdir -p /app/audit-logs /app/wordlists && \
    chown -R veilcams:veilcams /app

# Copy wordlists
COPY wordlists/ ./wordlists/

USER veilcams

ENTRYPOINT ["node"]
CMD ["dist/temporal/worker.js"]
