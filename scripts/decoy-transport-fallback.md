# 设计评估：ws / xhttp 传输层回落到伪装站

状态：**待批准，尚未实施**
目标读者：维护这个 fork 和 N2X 的人
约束：必须遵守 [README.md](./README.md) 的「Keep the divergence additive」

---

## 1. 要解决什么

VLESS/Trojan 的 `fallbacks` 挂在协议层。浏览器访问 `network` 为 ws / xhttp 的节点时，请求在**传输层**就被 `404` 打发掉了，协议层根本没被调用，所以协议层的回落永远触发不了。

```
transport/internet/websocket/hub.go   ServeHTTP  Host 不匹配 → 404 / Path 不匹配 → 404
transport/internet/splithttp/hub.go   ServeHTTP  Host 不匹配 → 404 / Path 不匹配 → 404
```

目标：这四处不再返回裸 `404`，而是把请求反代给本机伪装站，让 443 端口在浏览器里呈现为一个正常网站。

---

## 2. 冲突预算：为什么否决「加配置字段」

先量化。以下是 `upstream/main` 近两年的提交数：

| 文件 | 近 2 年提交数 | 说明 |
|---|---|---|
| `infra/conf/transport_internet.go` | **117** | 全仓最烫的文件之一 |
| `transport/internet/splithttp/hub.go` | 38 | 文件级很烫 |
| `transport/internet/splithttp/config.pb.go` | 22 | 生成物，整文件重写 |
| `transport/internet/splithttp/config.proto` | 15 | |
| `transport/internet/httpupgrade/hub.go` | 5 | |
| `transport/internet/websocket/hub.go` | 4 | |
| `transport/internet/websocket/config.proto` | 1 | |

「加一个 `fallback` 配置字段」的完整代价是：
`splithttp/config.proto` + `websocket/config.proto` + **两个 `config.pb.go` 重新生成** + `infra/conf/transport_internet.go` 加 JSON 解析。

最后那个文件两年 117 次提交，等于**每次同步上游几乎必冲突**；而 `.pb.go` 是生成物，冲突后不能手工合，只能重新生成再核对字段号有没有和上游新增字段撞车。

**结论：不加 proto 字段，不碰 `infra/conf/`。**

## 3. 但是——热文件里有冷区域

`splithttp/hub.go` 文件级 38 次提交，容易让人以为碰不得。实际做 blame 看要改的那 12 行：

```
transport/internet/splithttp/hub.go:96-107
  b8c0768b1 2024-07-06  if len(h.host) > 0 && !internet.IsValidHTTPHost(...)
  c10bd2873 2024-06-18      writer.WriteHeader(http.StatusNotFound)
  8fe976d7e 2024-06-21  if !strings.HasPrefix(request.URL.Path, h.path)
  c10bd2873 2024-06-18      writer.WriteHeader(http.StatusNotFound)

transport/internet/websocket/hub.go:42-51
  7e3a8d3a0 2024-03-29      writer.WriteHeader(http.StatusNotFound)
  c7f7c08ea 2020-11-25      writer.WriteHeader(http.StatusNotFound)
```

这两段自 2024 年年中起**没有再被上游动过**，ws 那行更是 2020 年的。该文件的 38 次提交全部集中在下方的 session / mux / 上传队列逻辑，和入口校验区不重叠。

**冷区域里的单行改动，冲突风险很低。**

---

## 4. 推荐方案

### 4.1 origin 从环境变量取，不走配置

伪装站监听地址已经是环境变量 `N2X_ARTX_DECOY_LISTEN`，而且 N2X 主服务的 systemd unit 已经有：

```
EnvironmentFile=-/etc/N2X/artx-decoy.env
```

（见 `N2X-script/install.sh:1289`）

也就是说 **Xray 所在进程的环境里本来就有这个变量**，两个仓库都不需要新增任何配置管道。

开关用一个独立变量 `N2X_DECOY_TRANSPORT_FALLBACK`，由 N2X 在启动时按节点配置里的 `DecoyFallback` 调 `os.Setenv` 写入，保持用户侧仍然只有一个开关。

### 4.2 逻辑全部放新包

新增 `transport/internet/decoyfallback/`（新目录，天然零冲突）：

| 文件 | 内容 |
|---|---|
| `fallback.go` | 读环境变量、校验 loopback、懒构造 `httputil.ReverseProxy`、`ServeOrNotFound(w, r)` |
| `fallback_test.go` | 单测 |

`proxy/artx/fallback.go` 里已有可复用的部件（`newFallbackTransport`、`newReverseProxy`、`isLoopbackHost`、`stripForwardingHeaders`），并且有 1073 行测试背书。建议把这几个函数下沉到新包，让 `proxy/artx` 反过来引用它——**改的是我们自己的文件，不产生上游冲突**。

注意方向：不能让 `transport/internet/*` 去 import `proxy/artx`（传输层依赖代理层，且有成环风险）。

### 4.3 上游文件只改 4 行，且不动 import

四处 `writer.WriteHeader(http.StatusNotFound)` 各替换为一行调用：

```go
// 原
writer.WriteHeader(http.StatusNotFound)
// 改为
internet.ServeDecoyOrNotFound(writer, request)
```

`ServeDecoyOrNotFound` 在未启用或反代失败时原样写 `404`，行为完全兜底。

**实施时的修正：调用的是 `internet.` 而不是 `decoyfallback.`。**

原计划让 hub 直接调用 `decoyfallback`，需要各加一行 import。实施前 blame 了两个 import 块：

```
websocket/hub.go  import 块   2020-12 起基本冻结
splithttp/hub.go  import 块   2026-03-09 / 2026-03-21 / 2026-04-05 三次新增
```

splithttp 的 import 块正在活跃增长，插入一行几乎必然在同步时冲突 —— 而 xhttp 恰好是主力传输。

改为在 `transport/internet/` 下新增一个文件（新文件零冲突）放转发函数。两个 hub 本来就 import 了这个包，而且就在拒绝分支的上一行调用 `internet.IsValidHTTPHost`，所以调用点不需要任何 import 改动。

**上游文件改动合计：2 个文件，4 行改动，0 行 import。** 现有漂移是 49 文件 / 10598 行，其中上游文件仅 4 个、共 30 行；这个增量低于既有约定。

代价：往上游的 `internet` 包命名空间里加了一个符号，理论上未来可能和上游新符号重名。那是编译错误而不是合并冲突，改个名即可，比每次同步都要手工解 import 冲突划算。

---

## 5. 明确不做

**`httpupgrade` 本轮不做。** 它的结构和另外两个不同：不是 `http.Handler`，而是在裸 `net.Conn` 上手工 `http.ReadRequest` 然后返回 error（`hub.go:53-67`）。要支持得走 `proxy/artx` 那套裸连接回落（`HTTPFallback.Serve(ctx, conn, prefix)`），是另一套集成。该传输使用率低，建议等 ws/xhttp 稳定后单独评估。

---

## 6. 运维注意事项（重要）

**xhttp 节点的 path 必须非空。**

`splithttp` 的匹配是前缀匹配，而空 path 会被规范化成 `/`（`transport/internet/splithttp/config.go:19-25`）：

```go
if path == "" || path[0] != '/' {
    path = "/" + path
}
```

一旦 path 为 `/`，`strings.HasPrefix(request.URL.Path, "/")` **恒为真**，永远不会走到 404 分支，伪装站也就永远不触发，而且浏览器的普通请求会被当成 xhttp 流量处理。

面板上给 xhttp 节点配一个具体路径（例如 `/xh8k2m`）是本功能生效的前提。ws 是精确匹配，不受此影响，但空 path 同样不是好实践。

---

## 7. 安全

- 反代目标**必须校验为 loopback**，复用 `isLoopbackHost`。环境变量一旦被改成外部地址就会变成 SSRF 跳板。
- 转发前清掉 `X-Forwarded-*`（复用 `stripForwardingHeaders`），避免把真实客户端 IP 泄漏给伪装站，也避免伪装站被诱导记录。
- 反代 transport 需要有连接数和响应头上限，`newFallbackTransport` 已经是有界的。
- 伪装站已支持 h2c，反代到它的是明文 HTTP，链路不出本机。

## 8. 副作用

环境变量是**进程级**的：开启后该 N2X 进程内所有 ws/xhttp 入站都会带上回落，无法按节点区分。这和 TCP 路径上按节点生效的 `DecoyFallback` 不一致。

要做到按节点区分就必须把开关送进 `StreamConfig`，也就回到第 2 节否决掉的 proto 改动。单机通常只跑少量同构节点，建议接受这个折中，并在 N2X 侧文档里写明。

---

## 9. 落地顺序

1. fork：新包 + 单测（不碰上游文件，可独立验证）
2. fork：`proxy/artx/fallback.go` 下沉公共部件，跑 artx 全量测试确认无回归
3. fork：4 处单行 hook + 2 行 import
4. fork：`go build ./... && go vet ./... && go test ./...`
5. **推送 fork 前需要你确认**（这一步会把代码发到 GitHub）
6. `./scripts/bump-n2x-pin.sh` 更新 N2X 的 replace pin 与 `UPSTREAMS.json`
7. N2X：`DecoyFallback` 为真且 network 为 ws/xhttp 时 `os.Setenv`
8. N2X：更新 `N2X_doc/gong-neng-shuo-ming/decoy-fallback.md` 的生效条件表
9. 端到端验证：xhttp 节点代理仍通 + 浏览器访问 443 出页面

第 1、2 步做完就能独立跑测试，是天然的检查点。

---

## 10. 备选方案与否决理由

| 方案 | 否决理由 |
|---|---|
| 传输层加 proto 配置字段 | 见第 2 节。要动 117 次提交/2 年的 `infra/conf/transport_internet.go` 和两个生成的 `.pb.go` |
| 外层 VLESS+TCP+TLS，按 path 回落到内层 ws 入站 | 对 xhttp 无效。`proxy/vless/inbound/inbound.go:384` 的 `first.Byte(4) != '*' // not h2c` 会在 h2 下跳过 path 匹配，而 xhttp 客户端优先 h2；且 path 是精确匹配，xhttp 的路径带动态段。另外 N2X 需要为单节点生成双入站 |
| 包装 `http.Handler`，拦截 404 响应再改写 | 上游文件只需 1 行/hub，冲突更低；但拦截器必须正确代理 `Hijacker`（ws 升级）和 `Flusher`（xhttp 流式），而 `splithttp/hub.go` 的流式逻辑正是上游高频改动区，功能性风险高于省下的那几行合并成本 |
| 前置 Nginx / Caddy | 能解决，但正是本需求要消除的运维负担 |
