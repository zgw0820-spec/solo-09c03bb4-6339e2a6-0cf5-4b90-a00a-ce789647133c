#!/usr/bin/env bash
# Nginx master 意外退出故障的真实端到端实测（真实 nginx + watcher + FastAPI）。
#
# 覆盖修复要求：
#  D. master 退出、watcher 存活：站点进程自动恢复，TLS 重新可握手
#  E. 不可达期间拒绝新启用（HTTP 503），不登记操作、不动 live 文件
#  F. 在途启用遇到 master 退出：不宣称"沿用旧证书"，保持待核实；
#     进程恢复后用新建 TLS 握手判明实际服务版本，据实结案并恢复接单
#  G. watcher 也停止（无人拉起）期间：持续拒单、在途操作持续待核实；
#     watcher 恢复接管后同样按实测结案
#  H. 恢复后实测为旧已登记版本：据实判失败并回退，而非凭回执文案下结论
#
# 前置：无（脚本自行 up/down 本地栈）。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK=/tmp/certops-local
WEB=http://127.0.0.1:8080
STACK="bash $ROOT/scripts/local_stack.sh"
PY="${PYTHON_BIN:-python3}"
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); echo "PASS  $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL  $1 ${2:-}"; }

jqp() { "$PY" -c "import json,sys;d=json.load(sys.stdin);print($1)"; }
live_fp() { openssl x509 -in "$WORK/live/fullchain.pem" -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }
served_fp() { openssl s_client -connect 127.0.0.1:8443 -servername demo.internal </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'; }
mkcert() { "$PY" "$ROOT/scripts/make_cert.py" --data-dir "$WORK/data" --out-dir "$1" >/dev/null; }
upload() { curl -s -F "cert_file=@$1/chain.pem" -F "key_file=@$1/key.pem" "$WEB/upload" | jqp "d['version_id']"; }
# 激活（不跟随重定向），输出 HTTP 状态码
activate_code() { curl -s -o /tmp/oc_body.json -w '%{http_code}' -F "version_id=$1" -F "base_version_id=$2" "$WEB/activate"; }
activate_body() { cat /tmp/oc_body.json; }
wait_until() {  # wait_until <描述> <命令: 成功返回0> [超时秒]
  local desc="$1" cmd="$2" timeout="${3:-20}" n=0
  while [ "$n" -lt "$((timeout * 2))" ]; do
    if eval "$cmd" >/dev/null 2>&1; then return 0; fi
    n=$((n+1)); sleep 0.5
  done
  echo "等待超时：$desc" >&2; return 1
}

$STACK down >/dev/null 2>&1
rm -rf "$WORK"
$STACK up >/dev/null || { echo "stack up failed"; exit 1; }

echo "=== 场景 D：master 退出后 watcher 自动拉起站点 ==="
V1FP=$(served_fp)
[ -n "$V1FP" ] && ok "D: 初始 TLS 可握手，服务版本 #1 指纹" || bad "D: 初始握手失败"
OLDPID=$($STACK nginx-pid)
$STACK kill-nginx >/dev/null
# watcher 每 0.3s 巡检一次，应在数秒内自动拉起；轮询等待新 master 出现
NEWPID=""
for i in $(seq 1 40); do
  CUR=$($STACK nginx-pid)
  if [ -n "$CUR" ] && [ "$CUR" != "$OLDPID" ] && kill -0 "$CUR" 2>/dev/null; then NEWPID=$CUR; break; fi
  sleep 0.25
done
[ -n "$NEWPID" ] && ok "D: nginx 已由 watcher 自动重新拉起（旧 pid=$OLDPID 新 pid=$NEWPID）" || bad "D: 未观察到自动恢复"
wait_until "D: 恢复后 TLS 可握手" "test -n \"\$(served_fp)\"" 10
[ "$(served_fp)" = "$V1FP" ] && ok "D: 恢复后新建握手仍返回版本 #1 证书" || bad "D: 恢复后指纹不符"
# 多杀几次，验证看守持续有效（每次都能自恢复）
$STACK kill-nginx >/dev/null
wait_until "D: 第二次自动恢复" "test -n \"\$(served_fp)\"" 10 && ok "D: master 再次退出后仍能自动恢复" || bad "D: 二次恢复失败"

echo "=== 场景 E：不可达期间拒绝新启用 ==="
mkcert /tmp/og-e; VE=$(upload /tmp/og-e)
mkcert /tmp/og-e2; curl -s -F "cert_file=@/tmp/og-e2/chain.pem" -F "key_file=@/tmp/og-e2/key.pem" "$WEB/upload" >/dev/null
LIVE_BEFORE=$(live_fp); OPS_BEFORE=$(curl -s "$WEB/api/status" | jqp "len(d['ops'])")
# 同时停掉 watcher 与 nginx，制造持续不可达（避免自动恢复干扰拒单验证）
$STACK stop-watcher >/dev/null
$STACK kill-nginx >/dev/null
wait_until "TLS 不可达" "test -z \"\$(served_fp)\"" 10 || bad "E: 站点未按预期不可达"
CODE=$(activate_code "$VE" 1)
[ "$CODE" = "503" ] && ok "E: 不可达期间启用请求被拒 (HTTP 503)" || bad "E: 拒单状态码" "got=$CODE body=$(activate_body)"
grep -q "暂停" <(activate_body) && ok "E: 503 文案说明暂停接单与自动恢复" || bad "E: 错误文案"
[ "$(live_fp)" = "$LIVE_BEFORE" ] && ok "E: 拒单未改动 live 证书文件" || bad "E: live 文件被改动"
[ "$(curl -s "$WEB/api/status" | jqp "len(d['ops'])")" = "$OPS_BEFORE" ] && ok "E: 拒单未登记任何操作" || bad "E: 产生了操作流水"
curl -s "$WEB/" | grep -q "暂停新的证书启用" && ok "E: 管理页显示暂停横幅" || bad "E: 页面无暂停横幅"
curl -s "$WEB/" | grep -q 'disabled' && ok "E: 管理页启用按钮已禁用" || bad "E: 按钮未禁用"

echo "=== 场景 F：在途启用遇 master 退出，恢复后按实测结案 ==="
mkcert /tmp/og-f; VF=$(upload /tmp/og-f)
VFFP=$(openssl x509 -in /tmp/og-f/chain.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
# 恢复 watcher（nginx 仍停），watcher 会先把站点拉起
$STACK start-watcher >/dev/null
wait_until "站点恢复" "test -n \"\$(served_fp)\"" 15 || { echo "致命：watcher 恢复失败"; exit 1; }
sleep 1  # 让后台核实循环观察到"可达"稳态，避免恢复边沿干扰本场景
# 长回执超时与待核实宽限，保证执行期不可达时操作稳定保持待核实
RECEIPT_TIMEOUT=20 PENDING_TTL=120 $STACK restart-web >/dev/null
sleep 1
curl -s -F "version_id=$VF" -F "base_version_id=1" "$WEB/activate" >/tmp/og-f-result.json &
ACTPID=$!
# 等 live 文件切换为目标证书（启用已进入执行期、重载请求已发出或即将发出）
wait_until "live 切换为目标证书" "test \"\$(live_fp)\" = \"$VFFP\"" 10 || { echo "致命：启用未落盘"; kill $ACTPID 2>/dev/null; exit 1; }
# 先停 watcher 再杀 master：制造 master 意外退出且暂时无人拉起的不可达窗口
$STACK stop-watcher >/dev/null
$STACK kill-nginx >/dev/null
wait $ACTPID 2>/dev/null
FSTATE=$(jqp "d['op']['state']" < /tmp/og-f-result.json)
[ "$FSTATE" = "pending_verify" ] && ok "F: 在途启用未宣称沿用旧证书，状态为待核实" || bad "F: 操作状态" "state=$FSTATE body=$(cat /tmp/og-f-result.json)"
grep -q "沿用旧证书" <(jqp "d['op']['detail']" < /tmp/og-f-result.json) && bad "F: 仍出现误导性文案" "" || ok "F: 回执文案不再谎称旧证书仍在服务"
# 恢复前持续不可达、持续待核实、持续拒单（轮询确认停机，而非固定睡眠）
wait_until "F: TLS 不可达" "test -z \"\$(served_fp)\"" 5
[ -z "$(served_fp)" ] && ok "F: 故障期间新 TLS 连接不可建立" || bad "F: 故障期仍可握手"
CODE=$(activate_code "$VE" 1); [ "$CODE" = "503" ] && ok "F: 故障期间新启用继续被拒" || bad "F: 拒单" "code=$CODE"
# watcher 恢复接管并自动拉起：新 master 加载当前 live（目标证书）
$STACK start-watcher >/dev/null
wait_until "watcher 自动恢复站点" "test -n \"\$(served_fp)\"" 15 || { echo "致命：未恢复"; exit 1; }
wait_until "在途操作结案 succeeded" "test \"\$(curl -s $WEB/api/status | jqp \"d['latest_op']['state']\")\" = succeeded" 15 \
  || bad "F: 操作未结案" "$(curl -s $WEB/api/status | jqp "d['latest_op']")"
ok "F: 恢复后以新建握手核实目标版本已生效，操作结案"
[ "$(served_fp)" = "$VFFP" ] && ok "F: openssl 实测指纹为目标版本" || bad "F: 实测指纹不符"
wait_until "恢复接单" "test \"\$(curl -s $WEB/api/status | jqp \"d['site_available']\")\" = True" 10 \
  && ok "F: 结案后管理面恢复接单" || bad "F: 未恢复接单"

echo "=== 场景 G：watcher 也停止，恢复接管后同样据实结案 ==="
mkcert /tmp/og-g; VG=$(upload /tmp/og-g)
VGFP=$(openssl x509 -in /tmp/og-g/chain.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
BASE=$(curl -s "$WEB/api/status" | jqp "d['active_version_id']")
# 长回执超时与待核实宽限：站点在执行期内不可达时操作稳定保持待核实
RECEIPT_TIMEOUT=20 PENDING_TTL=120 $STACK restart-web >/dev/null
sleep 1
# 先停 watcher（nginx 仍在运行，预检可通过），提交后再杀 master，制造无人拉起
$STACK stop-watcher >/dev/null
curl -s -F "version_id=$VG" -F "base_version_id=$BASE" "$WEB/activate" >/tmp/og-g-result.json &
ACTPID=$!
wait_until "G: live 切换为目标证书" "test \"\$(live_fp)\" = \"$VGFP\"" 10 \
  || { echo "致命：启用未落盘"; kill $ACTPID 2>/dev/null; exit 1; }
$STACK kill-nginx >/dev/null
wait $ACTPID 2>/dev/null
GSTATE=$(jqp "d.get('op',{}).get('state','')" < /tmp/og-g-result.json 2>/dev/null || echo "")
[ "$GSTATE" = "pending_verify" ] && ok "G: 无人拉起期间在途操作保持待核实" || bad "G: 操作状态" "state=$GSTATE body=$(cat /tmp/og-g-result.json 2>/dev/null)"
# 无 watcher：站点持续不可达，操作持续待核实，新启用持续被拒
wait_until "G: TLS 不可达" "test -z \"\$(served_fp)\"" 5
[ -z "$(served_fp)" ] && ok "G: 无 watcher 时站点不会自行恢复" || bad "G: 站点意外恢复"
CODE=$(activate_code "$VE" "$BASE"); [ "$CODE" = "503" ] && ok "G: 不可达期间持续拒单" || bad "G: 拒单" "code=$CODE"
# watcher 恢复接管，拉起 nginx 并加载目标证书
$STACK start-watcher >/dev/null
wait_until "G: watcher 接管后站点恢复" "test -n \"\$(served_fp)\"" 15 || { echo "致命"; exit 1; }
wait_until "G: 操作结案" "test \"\$(curl -s $WEB/api/status | jqp \"d['latest_op']['state']\")\" = succeeded" 15 \
  || bad "G: 未结案" "$(curl -s $WEB/api/status | jqp "d['latest_op']")"
ok "G: watcher 恢复后按新建握手核实并结案"
[ "$(served_fp)" = "$VGFP" ] && ok "G: openssl 实测为目标版本" || bad "G: 指纹不符"

echo "=== 场景 H：恢复后实测为旧已登记版本，据实判失败并回退 ==="
BASE=$(curl -s "$WEB/api/status" | jqp "d['active_version_id']")
mkcert /tmp/og-h; VH=$(upload /tmp/og-h)
VHFP=$(openssl x509 -in /tmp/og-h/chain.pem -fingerprint -sha256 -noout | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
OLD_FP=$(curl -s "$WEB/api/status" | jqp "d['active']['fingerprint']")
# 制造在途待核实操作后，让站点恢复时仍服务旧证书：
# 提交后立刻停 watcher、杀 master，再把 live 回滚为旧证书（模拟重载从未生效）
$STACK stop-watcher >/dev/null
RECEIPT_TIMEOUT=20 PENDING_TTL=120 $STACK restart-web >/dev/null
sleep 1
curl -s -F "version_id=$VH" -F "base_version_id=$BASE" "$WEB/activate" >/tmp/og-h-result.json &
ACTPID=$!
wait_until "H: live 切换为目标证书" "test \"\$(live_fp)\" = \"$VHFP\"" 10 || { echo "致命"; kill $ACTPID 2>/dev/null; exit 1; }
$STACK kill-nginx >/dev/null
wait $ACTPID 2>/dev/null
# 运维确认重载未生效，把 live 文件回滚为旧证书，再由 watcher 拉起（加载旧证书）
ACTIVE_CHAIN="$WORK/data/active_chain.pem"
"$PY" - "$WORK/data/certops.db" "$OLD_FP" "$WORK/live" <<'PYEOF'
import sqlite3, sys
db, want_fp, live = sys.argv[1:4]
conn = sqlite3.connect(db)
row = conn.execute("SELECT cert_pem,key_pem FROM versions WHERE fingerprint=?", (want_fp,)).fetchone()
assert row, "active version not found"
open(f"{live}/fullchain.pem","w").write(row[0])
open(f"{live}/privkey.pem","w").write(row[1])
print("live rolled back to active version")
PYEOF
$STACK start-watcher >/dev/null
wait_until "H: 站点恢复并服务旧证书" "test \"\$(served_fp)\" = \"$OLD_FP\"" 15 || { echo "致命"; exit 1; }
wait_until "H: 操作结案 failed" "test \"\$(curl -s $WEB/api/status | jqp \"d['latest_op']['state']\")\" = failed" 15 \
  || bad "H: 未判失败" "$(curl -s $WEB/api/status | jqp "d['latest_op']")"
ok "H: 握手确认旧已登记版本仍在服务，操作据实判失败"
DETAIL=$(curl -s "$WEB/api/status" | jqp "d['latest_op']['detail']")
echo "$DETAIL" | grep -q "握手" && ok "H: 结案依据写明新建 TLS 握手" || bad "H: 结案文案" "$DETAIL"
[ "$(curl -s "$WEB/api/status" | jqp "d['active_version_id']")" = "$BASE" ] && ok "H: 在用版本保持为旧版本 #$BASE" || bad "H: 在用版本被误改"
[ "$(live_fp)" = "$OLD_FP" ] && [ "$(served_fp)" = "$OLD_FP" ] && ok "H: live 文件与实测指纹均回到旧版本" || bad "H: 回退不彻底"

echo ""
echo "== nginx-outage: $PASS passed, $FAIL failed =="
$STACK down >/dev/null 2>&1
[ "$FAIL" -eq 0 ]
