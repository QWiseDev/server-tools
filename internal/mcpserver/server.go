package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"servermcp/internal/arthas"
	"servermcp/internal/auth"
	"servermcp/internal/dbquery"
	"servermcp/internal/logsw"
	"servermcp/internal/shell"
	"servermcp/internal/sysinfo"
)

// Deps 汇总 MCP 工具依赖的能力实现。
type Deps struct {
	Shell  *shell.Runner
	Logs   *logsw.Manager
	DB     *dbquery.Querier
	Arthas *arthas.Manager
	Keys   *auth.KeyStore
}

// ---- 各工具的输入/输出结构（jsonschema 描述会自动推导给 MCP 客户端）----

type execIn struct {
	Command string  `json:"command" jsonschema:"要执行的 shell 命令"`
	Timeout float64 `json:"timeout,omitempty" jsonschema:"超时秒数，默认 60，上限受 shell_timeout_max 约束"`
	Cwd     string  `json:"cwd,omitempty" jsonschema:"本次执行的工作目录，留空用服务端默认"`
}

type listProcIn struct {
	Sort  string `json:"sort,omitempty" jsonschema:"排序字段：cpu 或 mem，默认 cpu"`
	Limit int    `json:"limit,omitempty" jsonschema:"返回条数，默认 20，最大 100"`
}

type tailLogIn struct {
	Source string `json:"source" jsonschema:"文件路径（须在白名单内）或 docker:容器名"`
	Tail   int    `json:"tail,omitempty" jsonschema:"读取末尾行数，默认 300，最大 5000"`
	Grep   string `json:"grep,omitempty" jsonschema:"过滤：子串或 /正则/，如 /ERROR|Exception/"`
}

type searchLogIn struct {
	Source string `json:"source" jsonschema:"日志文件路径（须在 log_files/log_dirs 白名单内）"`
	Grep   string `json:"grep" jsonschema:"搜索模式：子串或 /正则/"`
	Limit  int    `json:"limit,omitempty" jsonschema:"单页最多命中条数，默认 200，最大 1000"`
	Offset int64  `json:"offset,omitempty" jsonschema:"上一页返回的 next_offset，用于续扫翻页"`
	CI     bool   `json:"ci,omitempty" jsonschema:"忽略大小写"`
}

type queryDBIn struct {
	SQL string `json:"sql" jsonschema:"单条 SELECT/WITH/EXPLAIN 语句"`
}

type arthasAttachIn struct {
	PID int `json:"pid" jsonschema:"目标 JVM 进程号"`
}

type arthasExecIn struct {
	Command string  `json:"command" jsonschema:"Arthas 只读命令，如 thread -n 5 / jvm / memory / trace / watch"`
	Timeout float64 `json:"timeout,omitempty" jsonschema:"超时秒数，默认 30，上限 120"`
}

// NewServer 构建并注册全部工具的 MCP Server。
func NewServer(d Deps, version string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "server-mcp", Version: version}, nil)
	srv.AddReceivingMiddleware(permissionMW(d.Keys))

	mcp.AddTool(srv, &mcp.Tool{Name: ToolExec, Description: "执行 shell 命令" +
		"（/bin/bash -lc），返回 exit_code/stdout/stderr/timed_out/duration_s；" +
		"超时按进程组整组强杀，受 shell_allow/shell_deny 正则约束"},
		func(ctx context.Context, req *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, shell.Result, error) {
			res, err := d.Shell.Run(in.Command, in.Timeout, in.Cwd)
			if err != nil {
				return nil, shell.Result{}, err
			}
			return nil, *res, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolOverview, Description: "服务器概况：运行时长、负载、" +
		"内存/磁盘使用率、CPU 前几名进程"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *sysinfo.Overview, error) {
			ov, err := sysinfo.GetOverview()
			return nil, ov, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolListProcesses, Description: "进程列表，按 cpu 或 mem 排序"},
		func(ctx context.Context, req *mcp.CallToolRequest, in listProcIn) (*mcp.CallToolResult, []sysinfo.Proc, error) {
			sortBy := in.Sort
			if sortBy == "" {
				sortBy = "cpu"
			}
			limit := in.Limit
			if limit == 0 {
				limit = 20
			}
			return nil, sysinfo.Processes(sortBy, limit), nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolListeningPorts, Description: "当前 TCP 监听端口及归属进程"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, []sysinfo.PortRow, error) {
			rows, err := sysinfo.ListeningPorts()
			return nil, rows, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolListLogs, Description: "列出可读的日志源：白名单文件 + 白名单 Docker 容器"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *logsw.Snapshot, error) {
			return nil, d.Logs.List(), nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolTailLog, Description: "读取日志。source 为文件路径（须在白名单内）" +
		"或 \"docker:容器名\"；grep 支持子串或 /正则/。适合按时间字符串或 request_id 过滤"},
		func(ctx context.Context, req *mcp.CallToolRequest, in tailLogIn) (*mcp.CallToolResult, *logsw.ReadResult, error) {
			tail := in.Tail
			if tail == 0 {
				tail = 300
			}
			res, err := d.Logs.Read(in.Source, tail, in.Grep)
			return nil, res, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolSearchLog, Description: "大日志文件全量搜索（流式扫描，内存恒定，" +
		"GB 级可用）：子串或 /正则/，返回全文件行号与命中内容；命中达到单页上限时返回 next_offset，" +
		"带该值再次调用即可续扫翻页。仅支持白名单文件，不支持 docker: 来源"},
		func(ctx context.Context, req *mcp.CallToolRequest, in searchLogIn) (*mcp.CallToolResult, *logsw.SearchResult, error) {
			res, err := d.Logs.Search(in.Source, in.Grep, in.Limit, in.Offset, in.CI)
			return nil, res, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolQueryDB, Description: "只读查询 config.json db_path 指定的" +
		" SQLite 数据库（仅 SELECT/WITH/EXPLAIN，单条语句）；db_path 未配置时不可用"},
		func(ctx context.Context, req *mcp.CallToolRequest, in queryDBIn) (*mcp.CallToolResult, *dbquery.QueryResult, error) {
			res, err := d.DB.Query(in.SQL)
			return nil, res, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolListJVMs, Description: "列出 JVM 进程（标注是否 Tomcat），" +
		"用于选择 Arthas attach 目标"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, []sysinfo.JVMProc, error) {
			return nil, sysinfo.ListJVMs(), nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolArthasStatus, Description: "Arthas 状态：是否安装、" +
		"是否已 attach、Web 控制台地址"},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *arthas.StatusResult, error) {
			return nil, d.Arthas.Status(), nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolArthasAttach, Description: "把 Arthas agent attach 到" +
		"指定 JVM pid（幂等：已 attach 则直接复用）"},
		func(ctx context.Context, req *mcp.CallToolRequest, in arthasAttachIn) (*mcp.CallToolResult, *arthas.AttachResult, error) {
			res, err := d.Arthas.Attach(in.PID)
			return nil, res, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: ToolArthasExec, Description: "执行 Arthas 只读排查命令并返回输出，" +
		"如 thread -n 5 / jvm / memory / trace / watch。禁止 ognl、redefine 等写命令"},
		func(ctx context.Context, req *mcp.CallToolRequest, in arthasExecIn) (*mcp.CallToolResult, string, error) {
			out, err := d.Arthas.Exec(in.Command, in.Timeout)
			return nil, out, err
		})

	return srv
}

// permissionMW 按 Bearer 密钥做两级控制：
//   - tools/call：密钥未授权该工具则直接拒绝，并记录 last_used
//   - tools/list：只返回该密钥被授权的工具
func permissionMW(keys *auth.KeyStore) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			key := keyFromRequest(keys, req)
			if key == nil {
				return nil, fmt.Errorf("无有效 MCP 密钥（Authorization: Bearer sk-...）")
			}
			if method == "tools/call" {
				p, ok := req.GetParams().(*mcp.CallToolParamsRaw)
				if ok {
					if !key.Allows(p.Name) {
						return nil, fmt.Errorf("密钥 %q 无工具 %s 的权限（%s）",
							key.Name, p.Name, ToolLabel(p.Name))
					}
					keys.Touch(key)
				}
			}
			res, err := next(ctx, method, req)
			if err == nil && method == "tools/list" {
				if lr, ok := res.(*mcp.ListToolsResult); ok {
					kept := lr.Tools[:0]
					for _, t := range lr.Tools {
						if key.Allows(t.Name) {
							kept = append(kept, t)
						}
					}
					lr.Tools = kept
				}
			}
			return res, err
		}
	}
}

// keyFromRequest 从 HTTP 头里的 Bearer 找到启用状态的密钥。
func keyFromRequest(keys *auth.KeyStore, req mcp.Request) *auth.Key {
	extra := req.GetExtra()
	if extra == nil || extra.Header == nil {
		return nil
	}
	token, ok := strings.CutPrefix(extra.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil
	}
	return keys.GetByKey(strings.TrimSpace(token))
}
