# 内网运维工具集（mTLS 诊断 + JWT 签名核验）

本仓库包含两个内网运维工具：

1. **mTLS 证书链离线诊断**（原有）：网关拒绝客户端证书时，区分中间证书缺失与交叉签发选链错误；
2. **JWT 签名核验**（新增）：登录服务更换签名公钥后，查清 JWT 被拒是**令牌本身错误**还是**密钥源（JWKS）故障**。

---

# 一、JWT 签名核验

## 要解决的问题

登录服务更换签名公钥后，运维拿到一个被拒的 JWT，需要立刻区分两种根因：

- **令牌无效（invalid）**：结构、算法、`kid`、`exp`、`iss`、`aud` 或签名本身有问题；
- **暂时无法核验（unknown）**：令牌格式没问题，但 JWKS 密钥源当前不可用，不能据此判断令牌真伪。

核验结论在页面上明确分为三态：**核验通过 / 令牌无效 / 暂时无法核验**，并显示具体原因。

## 信任边界（启动配置固定）

以下三项只从进程启动环境变量读取，**令牌内的 `jku` / `jwk` / `x5u` 等密钥地址一律不采信**：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `JWKS_URL` | `http://mock-jwks:8090/.well-known/jwks.json` | 唯一允许的 JWKS 地址 |
| `JWT_EXPECTED_ISSUER` | `https://login.intranet.example/realms/ops` | 固定预期 issuer |
| `JWT_EXPECTED_AUDIENCE` | `intranet-console` | 固定预期 audience |
| `JWKS_CACHE_TTL` | `60` | 整份 JWKS 成功刷新后的有效秒数 |
| `JWKS_REFRESH_MIN_INTERVAL` | `5` | 所有 kid 合计的最小刷新间隔秒数 |
| `JWKS_FETCH_TIMEOUT` | `2` | 单次 JWKS 请求超时秒数 |

## 核验规则（按顺序短路）

1. 必须是紧凑 JWS（恰好 3 段），base64url 与 JSON 可解码，签名段非空；
2. header `alg` 必须恰好为 **RS256**（`none`、HS256 等直接拒绝），且 `kid` 为**非空字符串**；
3. claims 必须包含**必填的数值型 `exp`** 且未过期（布尔值不算数值）；
4. `iss` 必须与固定配置完全相等；`aud` 为字符串时相等、为数组时包含预期值；
5. 以上全部通过后，才按 `kid` 向 JWKS 源取 RSA 公钥，做 RSASSA-PKCS1-v1_5 / SHA-256 验签。

令牌侧检查（1–4）失败 → `400 令牌无效`；只有走到密钥源且源不可用 → `503 暂时无法核验`。

## JWKS 缓存与刷新语义（单进程）

- 缓存**整份 JWKS 文档**，成功刷新后有效 60 秒；
- **命中有效缓存的请求直接核验，绝不等待任何刷新**；
- 仅在两种情况下刷新：**缓存过期**，或**令牌 `kid` 不在当前缓存中**；
- **并发刷新共用一次请求**（single-flight）：N 个并发冷请求只产生 1 次 HTTP；
- **所有 kid 合计每 5 秒最多发起一次请求**（全局节流，节流期内的请求不发 HTTP，直接得到可解释的失败）；
- 单次请求 **2 秒超时**；
- 新 JWKS 必须**整份合法**才替换：每个 key 都是 RSA 公钥、`kid` 非空且全文档唯一；空 `keys`、非法 JSON、重复 `kid`、非 RSA、带私钥参数 `d` 等都会被拒；
- 刷新失败**不清空旧缓存、不延长有效期**；缓存一旦过期，**绝不用旧钥放行**（旧缓存仅在仍有效时兜底）。

## 本地 JWKS 演示源（mock-jwks，独立进程，端口 8090）

内存中预置**两套 RSA 密钥套**（各含两个 `kid`）和一个带外密钥，支持：

- 一键在 `keyset-a` / `keyset-b` 间切换，模拟「签名公钥更换」；
- 故障注入：HTTP 500、空 `keys`、非法 JSON、`kid` 重复、响应超时（sleep 3s，超过核验端 2s 预算）；
- 按场景签发配套 JWT：正常、过期、缺 `exp`、iss/aud 不符、未知 `kid`、内容被篡改、alg=HS256、缺 `kid`、结构损坏等。

浏览器只访问核验服务（8080）一个源，演示控制经 `/demo/*` 同源代理转发到 mock。

## 快速开始（Docker Compose）

```bash
docker compose up --build -d
# 浏览器入口
open http://127.0.0.1:8080/verify     # Linux 可改用 xdg-open
# 也可直接访问 mock 源观察
open http://127.0.0.1:8090/__admin/state
```

推荐演示路径：

1. 在「配套 JWT 示例」点 **正常令牌** → 填入 → **核验通过**；
2. 点 **切换到密钥套 B（换公钥）**，等缓存 60 秒过期后再验旧令牌 → **令牌无效（签名失败）**；点新的正常令牌 → 又通过；
3. 点 **HTTP 500 / 超时** 等故障，缓存过期后核验 → **暂时无法核验（503）**；点 **恢复正常** 后自动复原。

停止：`docker compose down`

## HTTP 接口（JWT 部分）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/verify` | 核验页面（含缓存状态与演示控制台） |
| POST | `/verify` | 表单字段 `token`，返回三态 HTML（200/400/503） |
| POST | `/api/verify` | JSON `{"token": "..."}`，返回三态 JSON（200/400/503） |
| GET | `/api/jwks/cache` | 只读缓存诊断：是否有效、kid、年龄、剩余 TTL、请求次数、节流次数、上次错误 |
| GET/POST | `/demo/*` | 本地 JWKS 源的同源代理（状态、切密钥套、故障模式、取示例令牌、重置） |

---

# 二、mTLS 证书链离线诊断

内网 mTLS 运维排障场景：网关拒绝客户端证书时，区分两类根因——

1. **中间证书缺失**：叶子/中间证书的 issuer 在上传包中根本不存在；
2. **交叉签发选链错误**：存在同名（subject DN 相同）但密钥不同、或同一公钥被不同根交叉签发的多张证书，需要**验签后区分**，且一条候选链失败不能阻止其他链被枚举。

全部计算在本机离线完成，不发起任何网络请求，不检查吊销（CRL/OCSP）与证书用途（EKU）。

## 诊断范围与规则

- 输入：1 张客户端证书（leaf）+ 1 个无序中间证书 PEM 包 + 1 张独立指定的受信根 PEM；
  三类输入去重后**总计最多 12 张**证书。
- 签名策略：**仅支持 RSA PKCS#1 v1.5 / SHA-256**（OID `1.2.840.113549.1.1.11`），其他算法在全局提示与逐链结果中标为不支持。
- 从叶子出发 DFS 枚举**所有无环候选路径**（含环时只记录无环前缀，保证终止；有枚举上限保护）。
- 同名签发者必须先验证签名：同 DN 但验签失败的证书不会进入任何链，并在「同名签发者歧义」专区列出。
- 对每条候选链独立检查，任一链失败不影响其他链：
  - 每张证书在给定校验时间的有效期（notBefore 含、notAfter 不含）；
  - 每个签发者 `BasicConstraints cA=TRUE`；
  - `KeyUsage` 扩展**存在时**必须包含 `keyCertSign`（不存在不强制）；
  - 每个签发者的 `pathLenConstraint`（RFC 5280：只统计其下方非自颁发的中间 CA；终端实体叶子与自颁发中间证书不占 pathLen）；
  - 链必须终止于独立指定的受信根（根的自签名同样验证）。
- 输出：存在通过链时展示第一条通过的链；全部失败时逐条列出候选链、失败位置（链内下标）、错误码与原因；缺失签发者单独专区列出（含「同名但验签失败」明细）。

## 本地直接运行（两进程）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 终端 1：本地 JWKS 源
uvicorn app.mock_jwks:app --host 127.0.0.1 --port 8090
# 终端 2：核验服务（地址指向本地 mock）
JWKS_URL=http://127.0.0.1:8090/.well-known/jwks.json \
MOCK_JWKS_BASE=http://127.0.0.1:8090 \
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

## mTLS HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 浏览器上传页面（含 JWT 核验入口） |
| POST | `/diagnose` | multipart 表单：`leaf`、`intermediates`、`root`、`validation_time`（ISO 8601，无时区按 UTC），返回 HTML 结果页 |
| POST | `/api/diagnose` | 同入参，返回 JSON 诊断结果 |
| GET | `/api/examples/{name}` | 取内置示例的 manifest 与 PEM 文本 |
| GET | `/examples/{name}` | 303 跳转并由前端自动填充示例 |

## 内置 mTLS 示例

由 `scripts/generate_examples.py` 离线生成（一次性 RSA-2048 临时密钥）：

- **cross-sign**：`Intermediate CA X` 的同一公钥被 Root A / Root B 交叉签发，另含一张同 DN 不同密钥的陈旧证书；Root B 被放进中间包但不是受信根。预期两条候选链，一条通过、一条因终止于不受信根而失败。
- **all-fail**：默认叶子触发 pathLen 违规；替换 `alt-leaf-*.pem` 可分别复现签发者过期、KeyUsage 缺 keyCertSign、缺失签发者三种失败。

重新生成：`python3 scripts/generate_examples.py`

## 测试

```bash
pip install -r requirements.txt
python3 -m pytest -q
```

JWT 部分覆盖：

- JWKS 整份文档校验（RSA、唯一/非空 kid、拒绝私钥与非 RS256 alg）；
- 缓存 TTL、命中不刷新、未知 kid/过期才刷新、失败不清空不延长、过期不用旧钥；
- single-flight（20 并发冷请求仅 1 次 HTTP）、全局 5 秒节流、节流结果并发共享、2 秒超时；
- 核验器三态：RS256/kid 策略、必填数值 exp、iss/aud、签名失败、alg=none、各类畸形输入；
- Web/API 三态 HTTP 语义（200/400/503）、缓存诊断接口、演示代理；
- mock 源密钥套切换、全部故障模式、轮换后旧令牌签名失败。

mTLS 部分覆盖：简单链通过、中间证书缺失、交叉签发同名验签区分、不因首条失败中止枚举、有效期边界、pathLen 与自颁发豁免、KeyUsage、非 CA 签发、签名算法白名单、环终止、12 张上限、去重、受信根自签名检查、Web/API 端到端。

## 目录结构

```
app/
  config.py             # JWT 启动配置（iss/aud/JWKS 地址、TTL/节流/超时）
  jwks.py               # JWKS 整份缓存：single-flight、节流、超时、整份校验
  verifier.py           # RS256 JWT 严格核验（三态结果）+ 本地签名工具
  mock_jwks.py          # 本地可切换 JWKS 源（独立进程，两套公钥+故障注入）
  main.py               # FastAPI 路由（mTLS + JWT 页面/API/演示代理）
  diagnostics.py        # mTLS：PEM 解析、建图、全路径 DFS、逐链约束校验
  templates/            # Jinja2 页面（index / result / verify）
  static/               # CSS 与前端脚本（app.js / verify.js）
  examples/             # 内置 mTLS 交叉签发/全失败示例 PEM
scripts/generate_examples.py
tests/
Dockerfile, docker-compose.yml, requirements.txt, pyproject.toml
```

## 容器安全

两个容器均以非 root 用户运行，只读根文件系统、`tmpfs /tmp`、丢弃所有 Linux capabilities、`no-new-privileges`；端口仅绑定回环地址，核验服务经 compose 内部网络访问 mock，不暴露到公网。

