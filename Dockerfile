FROM node:20-alpine

WORKDIR /app

# WebUI、管理 API 与当前 Worker 一起封装，启动无需远程拉取代码。
COPY package.json package-lock.json server.js worker.js ./
RUN npm ci --omit=dev
COPY public ./public

# Create credentials dir (mounted at runtime)
RUN mkdir -p /app/credentials /app/data && chown -R node:node /app

USER node
EXPOSE 8787

CMD ["node", "/app/server.js"]
