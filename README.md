# server-mcp —— 通用服务器运维 MCP 服务端 + Web 控制台（Go）

单二进制提供三个入口，共享同一套运维能力（可执行 shell，其余偏只读）：

```
                    ┌────────────────────────────────────────┐
  ZCode (agent) ────►  /mcp       MCP streamable HTTP 端点    │
                    │            （Bearer 密钥，按工具授权）    │
  浏览器 (人)  ──────►  /         Web 控制台（密码登录）        │──► 核心能力
                    │  /api/*    控制台背后的 JSON API          │   ├─ 交互终端（PTY，等同 SSH）
                    │                                          │   ├─ Shell 执行（超时+强杀）
  Tailscale 内网层   │                                          │   ├─ 进程/端口/负载 (gopsutil)
  Tailscale 内网层   │                                          │   ├─ 日志 tail + grep（白名单）
                    └────────────────────────────────────────┘   ├─ SQLite 只读查询
                                                                 └─ Arthas attach/telnet
```

## 项目结构

```
serverMcp/
├── cmd/server/main.go        # 入口：装配配置/鉴权/能力，HTTP 服务与优雅退出
├── internal/
│   ├── config/               # config.json 加载 + 默认值 + 路径解析
│   ├── auth/                 # session.go 控制台会话；keys.go MCP 密钥存储（keys.json）
│   ├── shell/                # shell 执行：超时整组强杀 + allow/deny 正则
│   ├── sysinfo/              # 概况/进程/监听端口/JVM 发现（gopsutil）
│   ├── logsw/                # 白名单日志 tail + grep（文件/glob/目录/Docker）
│   ├── dbquery/              # SQLite 只读查询（modernc.org/sqlite，免 CGO）
│   ├── fsbrowse/             # 只读文件浏览：根目录白名单/目录列表/预览/下载
│   ├── arthas/               # telnet.go 迷你 telnet 客户端；arthas.go attach/执行
│   ├── mcpserver/            # tools.go 工具清单/权限分组；server.go 注册与按密钥过滤
│   ├── term/                 # 交互终端：PTY + WebSocket 桥接（creack/pty, gorilla/websocket）
│   ├── web/                  # 路由/鉴权中间件/JSON API；static/ 内嵌控制台页面（含 xterm.js）
│   └── textutil/             # UTF-8 安全截断
├── config.example.json       # 配置样例（复制为 config.json）
├── deploy/server-mcp.service # systemd 单元
└── .gitignore
```

## 能力清单

| MCP 工具 | Web 页面 | 说明 |
|---|---|---|
| `tool_exec` | Shell | 执行任意 shell 命令（`bash -lc`），返回 exit_code/stdout/stderr；超时按进程组整组强杀 |
| `tool_overview` | 总览 | 运行时长、负载、内存/磁盘、CPU Top |
| `tool_list_processes` | 进程 | 按 CPU/内存排序的进程表 |
| `tool_listening_ports` | 进程 | TCP 监听端口及归属进程 |
| `tool_list_logs` / `tool_tail_log` | 日志 | 白名单文件 + 白名单容器日志，tail + grep（子串或 `/正则/`） |
| `tool_search_log` | 日志 | 大文件全量搜索：子串或 `/正则/`、忽略大小写、全文件行号；分页续扫（`next_offset`），GB 级文件内存恒定 |
| `tool_query_db` | 数据库 | SQLite 只读查询，仅单条 SELECT/WITH/EXPLAIN；`db_path` 留空则关闭 |
| —（页面专属） | 终端 | 交互终端（WebSocket + PTY + xterm.js）：cd/环境保持、Tab 补全、Ctrl-C、vim/top 全屏程序，体验等同 SSH |
| —（页面专属） | 文件 | 只读文件浏览：目录列表/文本预览（尾部 256K，二进制识别）/下载，范围限 `fs_roots` 白名单 |
| `tool_list_jvms` | Arthas | JVM 进程列表（标注 Tomcat） |
| `tool_arthas_status` | Arthas | 安装/attach 状态、Web 控制台地址 |
| `tool_arthas_attach` | Arthas | attach 到指定 JVM（幂等） |
| `tool_arthas_exec` | Arthas | 执行只读排查命令：`thread` `jvm` `memory` `trace` `watch` `sc` `jad` 等 |

## 鉴权模型

两类凭证、两条边界：

- **Web 控制台 = 管理端**：`admin_password` 非空时，访问 `/api/*`（除 `/api/login`）都要先用密码换会话
  token（内存态，重启失效，默认 7 天）。控制台拥有全部权限，并可管理 MCP 密钥。
- **MCP 接入 = 密钥制**：`/mcp` 一律要求 `Authorization: Bearer sk-...`。每个密钥在控制台「密钥」页
  单独勾选可用工具：
  - 未授权的工具不会出现在该密钥的 `tools/list` 里，强行调用也会被拒绝；
  - 可停用（立即 401）、删除、改权限，停用后使用它的 MCP 客户端立刻失效；
  - 密钥存储在 `keys.json`（0600，原子写），服务首次启动时自动生成一个全权限 `default` 密钥并打印到日志；
  - 每个密钥记录最近使用时间。

## 安全模型

- **网络**：默认只绑 `127.0.0.1`；对外提供时绑 Tailscale IP（100.x），公网不可达。这是第一道防线。
- **文件浏览**：只读；路径先 realpath 解析再强制落在 `fs_roots` 白名单内，`..` 穿越与软链逃逸一律拒绝；
  预览上限 256K 并识别二进制；写操作请走 Shell（保持「shell 可写、其余只读」的一致边界）。
- **Shell 执行**：`shell_enabled` 总开关（同时控制交互终端）；`shell_timeout_max` 限制单次超时上限（默认 300s），
  超时对整个进程组 `SIGKILL` 不留孤儿；`shell_deny` 黑名单正则（优先级最高）；`shell_allow`
  白名单正则（非空时未命中即拒）。注意：名单只是绊线而非沙箱，shell 能做本用户权限内的任何事。
- **交互终端**：WebSocket + PTY，等同给管理员开了一条 SSH——受登录会话（含 cookie 通道）与
  `shell_enabled` 约束，并发上限 8；交互输入无法逐条过 allow/deny 名单，它是管理员的 shell，
  请像管理 SSH 账号一样管理控制台密码。断开即整组杀进程，不留孤儿。
- **日志白名单**：只读 `log_files`（支持 glob）与 `log_dirs` 前缀内的文件，以及 `docker_containers` 里的容器。
- **数据库只读**：`mode=ro` + `query_only` pragma + 语句类型白名单 + 单条限制 + 最多 500 行。
- **Arthas 黑名单**：禁止 `ognl` `redefine` `mc` `stop` `shutdown` 等写命令；单次执行硬超时 ≤120s。

## 构建与部署

```bash
# 本机构建（Apple Silicon）
GOOS=darwin GOARCH=arm64 go build -o server-mcp ./cmd/server

# 交叉编译 Linux 服务器版
GOOS=linux GOARCH=amd64 go build -o server-mcp ./cmd/server
```

```bash
# 服务器部署（宿主机，非容器：要看宿主机进程/执行宿主机 shell/读宿主机日志）
sudo mkdir -p /opt/server-mcp
sudo cp server-mcp config.example.json /opt/server-mcp/ && cd /opt/server-mcp
sudo cp config.example.json config.json   # 改 host/admin_password/日志白名单/shell 名单
sudo cp deploy/server-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now server-mcp
curl -s http://127.0.0.1:8808/healthz     # → ok
```

**Arthas（可选）**：需要 Java 深度诊断时装一次：

```bash
sudo mkdir -p /opt/arthas && cd /opt/arthas
sudo curl -LO https://github.com/alibaba/arthas/releases/latest/download/arthas-bin.zip
sudo unzip -q arthas-bin.zip
```

**attach 权限**：运行 server-mcp 的用户必须与目标 JVM 同用户（或 root）。

## 配置项（config.json）

| 字段 | 说明 |
|---|---|
| `host` / `port` | 监听地址；对外绑 Tailscale IP，纯本机用 127.0.0.1 |
| `admin_password` | 控制台登录密码；空 = 控制台免登录（仅建议纯本机） |
| `keys_path` | MCP 密钥存储路径；相对路径基于 config.json 所在目录 |
| `session_ttl_h` | 控制台会话有效期（小时，默认 168） |
| `shell_enabled` | 是否开放 shell 执行能力 |
| `shell_allow` / `shell_deny` | shell 命令白/黑名单正则；deny 优先，allow 非空时未命中即拒 |
| `shell_timeout_max` | 单次 shell 超时上限（秒，默认 300） |
| `shell_cwd` | shell 默认工作目录；留空用服务进程 cwd |
| `db_path` | SQLite 路径；留空关闭数据库查询 |
| `fs_roots` | 文件浏览白名单根目录（支持 `~`），如 `["~", "/var/log"]`；留空关闭文件浏览 |
| `log_files` | 日志文件/glob 白名单 |
| `log_dirs` | 允许读取的目录前缀 |
| `docker_containers` | 允许读日志的容器名 |
| `arthas_home` | 含 `arthas-core.jar` 的目录；留空自动找 `~/.arthas/lib/*/arthas` |
| `arthas_telnet_port` / `arthas_http_port` | 默认 3658 / 8563；多 JVM 共用，同时 attach 多个需改端口 |
| `java_bin` | 留空用 PATH 里的 java |
| `max_output` | 单次返回文本截断长度（字节） |

## ZCode 注册

1. 启动服务，浏览器打开控制台 `http://<host>:8808/`，用 `admin_password` 登录；
2. 「密钥」页 → 新建密钥（如 `zcode-本机`），勾选需要的工具，复制生成的 `sk-...`；
3. 写入 `~/.zcode/cli/config.json`（个人）或 `<repo>/.zcode/config.json`（团队共享）：

```json
{
  "mcp": {
    "servers": {
      "server-mcp": {
        "type": "http",
        "url": "http://100.x.y.z:8808/mcp",
        "headers": { "Authorization": "Bearer sk-xxxxxxxx" }
      }
    }
  }
}
```

重启会话后自动连接，工具名形如 `mcp__server-mcp__tool_exec`。改权限/停用密钥在控制台操作，立即生效。

## 本地自测记录（2026-09-29，macOS arm64 + Go 1.26 + go-sdk v1.8.0）

- 构建 + `go vet` ✅；单二进制含内嵌控制台页面
- 控制台鉴权：未登录 401 ✅；错误密码 401（含 500ms 延迟）✅；登录发会话 token ✅；登出后 401 ✅
- 密钥：首启自动生成 default（11 工具）✅；新建受限密钥 ✅；停用后 /mcp 立即 401 ✅；删除 ✅；删光重启自动重建 ✅；last_used 记录 ✅
- MCP：initialize → tools/list（default 11 个 / 受限密钥仅 2 个）✅；tools/call tool_exec 返回 exit_code 7 + stdout/stderr ✅
- 权限拒绝：受限密钥调 tool_exec → 明确报「密钥无工具权限」✅；shell_deny 命中 ✅
- Shell：超时 2s 准时 SIGKILL（exit -9, timed_out）✅；后台子进程整组强杀无残留 ✅；`shell_allow` 白名单命中放行/未命中拒绝 ✅；`cwd` 指定 ✅
- 日志白名单：白名单内可读 ✅；`/etc/passwd` 拒绝 ✅
- SQLite：只读查询（含中文）✅；INSERT 拒绝 ✅；db_path 留空报能力关闭 ✅
- 文件浏览：根视图/目录列表/尾部预览/二进制识别/下载 ✅；`/etc/passwd`、多级 `..` 穿越、软链逃逸全部拒绝 ✅；未登录 401 ✅
- 全文件搜索（10 万行/2.9MB 样本 + limit=1/2 强制分页）：子串/正则命中行号准确 ✅；续扫行号与全文件对齐（50001 → 100002）✅；ci 忽略大小写 ✅；非法正则 400 ✅；MCP tools/list 12 个工具、tool_search_log 翻页 ✅
- 交互终端（WS+PTY）：未登录握手 401 ✅；登录会话连接后命令回显 ✅；cd/环境变量跨命令保持 ✅；resize 控制帧生效 ✅；客户端断开后进程组整杀、无孤儿 ✅；xterm.js/fit-addon 由二进制内嵌伺服 ✅
