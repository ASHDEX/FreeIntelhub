FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies for better-sqlite3 native addon
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# ---

FROM node:20-alpine

WORKDIR /app

# Runtime dependency for better-sqlite3
RUN apk add --no-cache libstdc++

COPY --from=builder /app/node_modules ./node_modules
COPY . .

# Create db directory (will be overridden by volume mount)
RUN mkdir -p /app/db

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

USER node

CMD ["node", "app.js"]
