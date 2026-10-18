#!/bin/sh
# 容器入口:以 root 起步, 修正数据目录属主后降权到 node(uid 1000) 执行。
#
# 为什么需要:数据库与备份在挂载卷里, 而挂载目录的属主不由镜像决定 ——
#   - 命名卷若之前被 root 容器写过, 会保持 root:root
#   - PANEL_DATA_DIR 指向宿主目录时, Docker 会以 root 创建它
# 此时应用以 uid 1000 运行就写不进去, SQLite 抛 errcode 14
# "unable to open database file"(注意 mkdir 是成功的, 所以看不到 EACCES)。
set -e

if [ "$(id -u)" = "0" ]; then
  db_dir=$(dirname "${PANEL_DB:-/app/data/panel.db}")
  backup_dir="${PANEL_BACKUP_DIR:-/app/data/backups}"

  for d in "$db_dir" "$backup_dir"; do
    mkdir -p "$d"
    # 修不了也不要直接退出:某些网络文件系统(root_squash)本就不允许 chown,
    # 让它继续跑, 由应用给出更具体的错误。
    chown -R node:node "$d" 2>/dev/null ||
      echo "[entrypoint] 警告: 无法修改 $d 的属主, 若数据库打不开请检查挂载目录权限" >&2
  done

  exec su-exec node:node "$@"
fi

# 容器本身以非 root 启动(如 --user 任意 uid), 原样执行
exec "$@"
