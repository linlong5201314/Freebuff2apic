FROM node:20-alpine

# su-exec：启动时以 root 修正挂载卷归属后降权到 node 用户
RUN apk add --no-cache su-exec

WORKDIR /app

# WebUI、管理 API 与当前 Worker 一起封装，启动无需远程拉取代码。
COPY package.json package-lock.json server.js worker.js ./
RUN npm ci --omit=dev
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Create credentials dir (mounted at runtime)
RUN mkdir -p /app/credentials /app/data && chown -R node:node /app \
  && chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8787

# 以 root 启动 entrypoint：修正 /app/data（挂载卷）所有权后降权运行
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "/app/server.js"]
