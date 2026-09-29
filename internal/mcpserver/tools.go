// Package mcpserver 注册 server-mcp 的全部 MCP 工具，并按接入密钥做权限过滤。
package mcpserver

// 工具名常量：MCP 工具名与「密钥可授予的工具集」共用这一份清单。
const (
	ToolExec           = "tool_exec"
	ToolOverview       = "tool_overview"
	ToolListProcesses  = "tool_list_processes"
	ToolListeningPorts = "tool_listening_ports"
	ToolListLogs       = "tool_list_logs"
	ToolTailLog        = "tool_tail_log"
	ToolSearchLog      = "tool_search_log"
	ToolQueryDB        = "tool_query_db"
	ToolListJVMs       = "tool_list_jvms"
	ToolArthasStatus   = "tool_arthas_status"
	ToolArthasAttach   = "tool_arthas_attach"
	ToolArthasExec     = "tool_arthas_exec"
)

// Group 是控制台「密钥」页展示用的权限分组。
type Group struct {
	Name  string   `json:"name"`
	Tools []string `json:"tools"`
}

// Groups 是全部工具的分组视图（顺序即控制台勾选顺序）。
var Groups = []Group{
	{"Shell", []string{ToolExec}},
	{"系统", []string{ToolOverview, ToolListProcesses, ToolListeningPorts}},
	{"日志", []string{ToolListLogs, ToolTailLog, ToolSearchLog}},
	{"数据库", []string{ToolQueryDB}},
	{"Arthas", []string{ToolListJVMs, ToolArthasStatus, ToolArthasAttach, ToolArthasExec}},
}

// AllTools 返回全部工具名。
func AllTools() []string {
	var out []string
	for _, g := range Groups {
		out = append(out, g.Tools...)
	}
	return out
}

// ValidTools 返回工具名集合（密钥校验用）。
func ValidTools() map[string]bool {
	m := map[string]bool{}
	for _, t := range AllTools() {
		m[t] = true
	}
	return m
}

// ToolLabel 返回工具的可读分组标签，如 "Shell / tool_exec"。
func ToolLabel(tool string) string {
	for _, g := range Groups {
		for _, t := range g.Tools {
			if t == tool {
				return g.Name + " / " + tool
			}
		}
	}
	return tool
}
