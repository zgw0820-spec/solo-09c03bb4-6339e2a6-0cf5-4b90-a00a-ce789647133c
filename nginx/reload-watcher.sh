#!/bin/sh
# 与 web 侧约定：web 向 $RELOAD_DIR/REQUEST 追加一行令牌，
# 本脚本检测到新行后执行 nginx -t && nginx -s reload（平滑重载，旧连接自然完成），
# 并把结果以 "令牌 ok|fail 原因" 追加到 $RELOAD_DIR/RESULT。
#
# 看守职责：每个循环先检查 nginx master 是否存活（以 pid 文件 + kill -0 判据），
# master 意外退出时自动重新拉起，使站点在 watcher 存活期间自行恢复；
# master 不存活时到达的重载请求不会被谎报成功，待 master 恢复后再执行并据实写回执。
set -u

RELOAD_DIR="${RELOAD_DIR:-/reload}"
LIVE_DIR="${LIVE_DIR:-/etc/nginx/certs/live}"
NGINX_BIN="${NGINX_BIN:-nginx}"
NGINX_ARGS="${NGINX_ARGS:-}"
NGINX_PID_FILE="${NGINX_PID_FILE:-/var/run/nginx.pid}"
REQ="$RELOAD_DIR/REQUEST"
RES="$RELOAD_DIR/RESULT"

mkdir -p "$RELOAD_DIR"
touch "$REQ" "$RES"

# 单实例保护：同一 REQUEST 文件只允许一个 watcher 看守。
# flock 随进程退出自动释放，异常崩溃后不会留下死锁。
LOCK_FD=9
# shellcheck disable=SC2093
exec 9>"$REQ.lock"
if command -v flock >/dev/null 2>&1; then
  if ! flock -n "$LOCK_FD"; then
    echo "reload-watcher: 已有另一 watcher 在看守 $REQ，本实例退出" >&2
    exit 0
  fi
fi

# 首次启动时等待 web 侧生成证书文件
n=0
while [ ! -s "$LIVE_DIR/fullchain.pem" ] || [ ! -s "$LIVE_DIR/privkey.pem" ]; do
  n=$((n + 1))
  if [ "$n" -gt 600 ]; then
    echo "reload-watcher: 等待证书文件超时" >&2
    exit 1
  fi
  sleep 0.5
done

# master 存活判据：pid 文件存在、内容为数字、对应进程确实存在。
# 无 pid 文件时退回进程名探测（兼容非标准启动方式）。
nginx_alive() {
  if [ -s "$NGINX_PID_FILE" ]; then
    pid=$(cat "$NGINX_PID_FILE" 2>/dev/null)
    case "$pid" in
      ''|*[!0-9]*) return 1 ;;
      *) kill -0 "$pid" 2>/dev/null && return 0 || return 1 ;;
    esac
  fi
  pgrep -x "${NGINX_BIN##*/}" >/dev/null 2>&1
}

# pid 文件可能由 nginx 按配置路径写出（与 NGINX_PID_FILE 不同时），
# 启动/拉起后轮询等待其落地，避免立刻误判 master 不存活而重复拉起。
wait_pid_file() {
  n=0
  while [ ! -s "$NGINX_PID_FILE" ]; do
    n=$((n + 1))
    [ "$n" -gt 50 ] && return 1
    # 文件迟迟不出现但进程已在运行：以进程名探测结果为准
    pgrep -x "${NGINX_BIN##*/}" >/dev/null 2>&1 || return 1
    sleep 0.1
  done
  return 0
}

start_nginx() {
  # shellcheck disable=SC2086
  $NGINX_BIN $NGINX_ARGS
}

# shellcheck disable=SC2086
start_nginx || exit 1
wait_pid_file || true
echo "reload-watcher: nginx started, watching $REQ" >&2

last_count=$(wc -l < "$REQ" | tr -d ' ')
while :; do
  sleep 0.3

  # 1) 看守：master 意外退出则自动拉起（watcher 本身存活即恢复站点）
  if ! nginx_alive; then
    echo "reload-watcher: nginx master 不在运行，尝试重新拉起" >&2
    if start_nginx; then
      wait_pid_file || true
      echo "reload-watcher: nginx 已恢复，重新加载当前 live 证书" >&2
    else
      echo "reload-watcher: nginx 拉起失败，下个循环重试" >&2
      continue
    fi
  fi

  cur_count=$(wc -l < "$REQ" 2>/dev/null | tr -d ' ' || echo 0)
  case "$cur_count" in ''|*[!0-9]*) cur_count=0 ;; esac
  [ "$cur_count" -le "$last_count" ] && continue

  # 2) 处理积压的重载请求；执行前再次确认 master 存活
  if ! nginx_alive; then
    continue  # 不写回执：恢复后由后续循环据实处理，web 侧按回执超时转待核实
  fi

  # shellcheck disable=SC2086
  if $NGINX_BIN $NGINX_ARGS -t >/tmp/nginx-t.err 2>&1; then
    # shellcheck disable=SC2086
    if $NGINX_BIN $NGINX_ARGS -s reload >/tmp/nginx-r.err 2>&1; then
      result="ok"
    else
      result="fail reload: $(tail -n 1 /tmp/nginx-r.err)"
    fi
  else
    result="fail test: $(tail -n 1 /tmp/nginx-t.err)"
  fi

  # 同一批新行共享本次重载结果（后写文件的操作先于重载落盘，语义安全）
  sed -n "$((last_count + 1)),${cur_count}p" "$REQ" | while read -r token _; do
    [ -n "$token" ] && echo "$token $result" >> "$RES"
  done
  last_count=$cur_count
done
