# Build-Kontext ist das Repo-Root: docker build -f web/Dockerfile .
FROM node:22-slim AS deps
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci

FROM node:22-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules node_modules
COPY web/ ./
RUN npm run build

FROM node:22-slim
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
WORKDIR /app
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin patchwatch
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
USER 10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/login').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.js"]
