#!/bin/sh
set -e

# Railway / docker compose 挂载的卷默认归 root 所有，而应用以 node 用户运行，
# 会报 EACCES: permission denied, open '/app/data/accounts.json'。
# 容器以 root 启动：先把 /app/data 归属修正为 node，再降权运行主进程。
if [ "$(id -u)" = "0" ]; then
  mkdir -p /app/data
  chown -R node:node /app/data 2>/dev/null || true
  exec su-exec node:node "$@"
fi

# 已经是非 root 环境时直接运行
exec "$@"
