# 单站点 TLS 证书启用管理

机房运维在网页上为内网站点（演示域名 `demo.internal`）替换 TLS 证书。
启用结果以 **Nginx 新建 TLS 连接实际返回的证书指纹** 为唯一判据。

## 架构

```
┌────────────┐   共享卷 certs/live    ┌──────────────────────────┐
│  web       │ ───────────────────▶ │  nginx（站点 :443）       │
│  FastAPI   │   共享卷 reload       │  + reload-watcher.sh     │
│  + SQLite  │ ◀─────────────────── │  （检测 REQUEST →        │
└────────────┘   REQUEST/RESULT 回执 │   nginx -t && -s reload） │
      │ 新建 TLS 连接探测指纹         └──────────────────────────┘
      └──────────────────────────────────────▶
```

- **web**（`web/`）：FastAPI + SQLite。上传校验、启用编排、并发控制、
  重启对账、后台核实循环。管理页 `:8080`。
- **nginx**（`/nginx/`）：提供 TLS 站点；旁挂 watcher 脚本按文件令牌执行
  `nginx -t && nginx -s reload`（平滑重载，旧连接自然完成）并写回执；
  同时看守 master 进程，master 意外退出时自动重新拉起（单实例 flock 保护）。

## 运行

```bash
docker compose up --build
# 管理页  http://localhost:8080
# 站点    https://localhost:8443  （建议 /etc/hosts 加 127.0.0.1 demo.internal）
```

首次启动自动生成演示 CA 与"旧证书"（版本 #1，在用）。
用 `scripts/make_cert.py --data-dir <数据目录> --out-dir /tmp/newcert`
可签发演示新证书用于上传（生产环境上传真实 CA 签发的证书即可）。

无 Docker 时本地验证：`bash scripts/local_stack.sh up`（需 nginx 二进制，
见 `NGINX_BIN` 环境变量）。

## 关键规则实现

| 需求 | 实现 |
| --- | --- |
| 上传校验 | `certutil.validate_upload`：密钥匹配（公钥 DER 对比）、域名（SAN/CN，含单层通配）、有效期、链逐级签发验证 |
| 页面所见版号 | 启用表单携带 `base_version_id`；`BEGIN IMMEDIATE` 事务内比较-交换，不一致即 409「页面版号已过期」 |
| 并发/重复提交 | 同一事务内拒绝已存在 `activating` 操作；重复提交因版号失效被拒；上传按指纹去重 |
| 启用成功判据 | 仅当新建 TLS 连接返回新证书指纹才置 `succeeded` |
| 站点进程自愈 | watcher 每 0.3s 以 pid 文件 + `kill -0` 检查 master，意外退出即自动重新拉起；flock 保证单实例看守 |
| 不可达期间拒单 | 启用前先做新建 TLS 握手预检，不可达直接 503 拒绝：不写文件、不发重载、不登记操作；页面显示暂停横幅并禁用按钮 |
| 重载失败不谎报 | `fail` 回执不再直接宣称「沿用旧证书」：必须再做新建握手，实测旧已登记版本仍在服务才判失败并回退；实测指纹未登记或无法握手则保持「待核实」 |
| 在途操作恢复结案 | 站点不可达时在途操作保持 `pending_verify`；恢复后由后台循环以新建握手判明实际服务的**已登记版本**，匹配目标即成功、匹配其他已登记版本即失败回退；实测指纹未登记则继续待核实，超时也不强行结案 |
| 回执不明/重启 | 操作置 `pending_verify`（页面显示"待核实"）；进程重启时按 Nginx 实际服务指纹对账，恢复到可确认的在用版本 |
| 旧操作不覆盖新提交 | 任何落库/写文件前检查 `current_op_seq`；新操作创建时把待核实旧操作置 `superseded` |
| 已有连接 | nginx 平滑重载，旧 worker 服务完旧连接再退出 |

## 验证

```bash
cd web && python3 -m pytest tests/ -q          # 30 项单元/集成测试
bash scripts/local_stack.sh up && python3 scripts/e2e_check.py       # 19 项真实端到端
bash scripts/interrupt_check.sh                # 10 项崩溃/中断恢复实测
bash scripts/nginx_outage_check.sh             # 26 项 master 退出/自愈/拒单/恢复结案实测
```

## 说明与限制

- 单实例管理进程（SQLite + 进程内锁），不适用于多副本部署。
- 演示用 CA 私钥存于数据目录 `ca/`，仅为签发演示证书；生产应上传外部签发证书。
- nginx 与 web 之间经共享卷文件通信，回执超时（默认 6s）即视为"回执不明"。
- watcher 自愈依赖容器本身存活：master 退出会被自动拉起；若容器整体退出需由
  容器编排（如 Docker `restart` 策略、K8s 探针）重建容器。
