# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Build
# Clones UnitTCMS from the official GitHub repo, injects the PIAP custom seed
# and entrypoint, then builds the Next.js frontend.
# ──────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

RUN apk add --no-cache git libc6-compat

WORKDIR /build

# Clone official UnitTCMS source (shallow clone for speed)
RUN git clone --depth 1 https://github.com/kimatata/unittcms.git .

# Install root, frontend, and backend dependencies
RUN npm ci
RUN cd frontend && npm ci
RUN cd backend && npm ci

# ── Inject PIAP customisations ───────────────────────────────────────────────
# Replace default demo seed with PIAP Cisco Secure Access test cases
COPY seed.js ./backend/seeders/seed.js

# Replace entrypoint with version that handles re-seed gracefully on restart
COPY entrypoint.js ./entrypoint.js
# ─────────────────────────────────────────────────────────────────────────────

# Build Next.js frontend (standalone output)
RUN cd frontend && npm run build

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Production image
# ──────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8000
ENV FRONTEND_ORIGIN=http://localhost:8000

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Backend (includes our custom seed.js)
COPY --from=builder /build/backend ./backend

# Next.js standalone build
COPY --from=builder /build/frontend/.next/standalone ./
COPY --from=builder /build/frontend/.next/static ./.next/static
COPY --from=builder /build/frontend/public ./public

# Next.js module needed by the entrypoint server
COPY --from=builder /build/node_modules/next ./node_modules/next

# Install backend dependencies natively in the final image
WORKDIR /app/backend
COPY --from=builder /build/backend/package.json ./
COPY --from=builder /build/backend/package-lock.json ./
RUN npm ci

WORKDIR /app

# Custom entrypoint (graceful re-seed)
COPY --from=builder /build/entrypoint.js ./

EXPOSE 8000

CMD ["node", "entrypoint.js"]
