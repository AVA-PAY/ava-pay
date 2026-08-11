# Production image for the AVA Pay Shopify app (Railway service ava-pay-shopify).
#
# The Railway service sets Root Directory to shopify-app, so the build context
# is this directory and the app builds independently of the API workspace.
#
# Prisma on Alpine needs openssl present in both stages: the build stage to
# generate the client, the run stage for the query engine and migrate deploy.

FROM node:22-alpine AS builder
WORKDIR /app
RUN apk add --no-cache openssl

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY prisma ./prisma
RUN npx prisma generate

COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl

ENV NODE_ENV=production
# react-router-serve binds 0.0.0.0 and reads PORT. Never set HOST here: the
# server treats it as the bind address, not the public URL (that is
# SHOPIFY_APP_URL). Railway overrides PORT with its own value.
ENV PORT=3000

# Production dependencies only. The prisma CLI is a runtime dependency because
# the entrypoint runs `prisma migrate deploy` on every start.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY --chown=node:node prisma ./prisma
RUN npx prisma generate

COPY --from=builder --chown=node:node /app/build ./build
COPY --chown=node:node docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Nothing here needs root: the database is remote and no volume is mounted.
USER node

EXPOSE 3000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["npm", "run", "start"]
