# 深空中继 · DTLS 1.3 记录审计服务

审查员用于复核深空中继加密遥测捕获的服务：确认**重复捕获、过期序号、伪造的
KeyUpdate** 不会被当作新的有效指令。零依赖 Node.js（≥18）实现。

## 范围与规则

- 仅接受 **无 CID 的 DTLS 1.3 统一头**、**TLS_AES_128_GCM_SHA256**、**单方向**记录；
- 从原始头部（8/16 位低比特 + 接收状态）恢复 48 位序号（RFC 9147 §4.2.2.1）；
- 按 DTLS 标签派生密钥与 IV：`HKDF-Expand-Label(secret, "key"/"iv", "")`，
  前缀 `"dtls13 "`；KeyUpdate 后以 `"traffic upd"` 派生下一代表流量秘密；
- **AEAD 认证成功后才解开内部内容类型**（`content || type || zeros`）；
- 接收状态 = 每个 epoch 的最高序号 + 64 位位图，裁定 新到 / 重复 / 过旧；
- KeyUpdate 必须先通过认证与重放裁定，才派生下一 epoch 密钥并**重置窗口**；
  失败、重复或旧 epoch 记录**绝不推进秘密或窗口**；
- 裁决报告首个截断 / 长度 / 认证 / 状态违规的**原始字节偏移**；重新提交同一
  审计标识会原子替换旧裁决（清除该次旧成功证据）。

## 运行

```bash
# Docker（宿主机端口可配置，默认 8080）
HOST_PORT=9000 docker compose up --build app

# 或本地
node src/server.js          # PORT=8080 DATA_DIR=./data
```

打开 `http://localhost:8080/`：填写审计标识、初始接收 epoch、64 位十六进制
traffic secret，按捕获顺序粘贴至多 48 条 Base64 记录。提交后可凭审计标识
**重新打开冻结裁决**，查看每条记录的 epoch、序号、认证结果、重放窗口前后
状态与应用数据摘要（SHA-256）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康响应 |
| POST | `/api/audits` | 提交审计，冻结并返回裁决（替换同标识旧裁决） |
| GET | `/api/audits/:id` | 重新打开冻结裁决 |

提交体：

```json
{
  "audit_id": "relay-pass-1",
  "initial_epoch": 2,
  "traffic_secret": "<64 hex chars>",
  "records": ["<base64 record>", "..."]
}
```

## 验收（verify 容器）

```bash
docker compose up --build --exit-code-from verify
```

`verify` 容器等待 `app` 健康后依次执行，并以**退出状态码**报告验收结果：

1. **构建检查** — 全部源文件语法解析、必需文件与 compose 配置存在；
2. **复核规则测试** — `node --test`：密钥调度 KAT、序号恢复、64 位窗口
   边界（63/64）、KeyUpdate 推进与窗口重置、伪造/重放 KeyUpdate 不推进状态；
3. **HTTP 冒烟** — 针对密钥更新与重放边界的真实 API 场景（合法推进、
   旧 epoch 拒绝、伪造认证失败偏移、重复不推进窗口、旧成功证据被清除）。

本地等价命令：`node src/server.js &` 然后 `node verify/run.js`
（`APP_URL` 默认 `http://127.0.0.1:8080`）。

## 布局

```
src/dtls13.js   记录层解析、密钥调度、重放窗口、审计引擎
src/server.js   HTTP API 与静态页面
src/store.js    冻结裁决的原子持久化
public/         审计页面（中文）
verify/         复核规则测试、构建检查、HTTP 冒烟、编排器
```
