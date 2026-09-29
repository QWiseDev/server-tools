// Package term 提供基于 PTY 的交互式终端：WebSocket 双向桥接用户浏览器
// 与一个登录态交互 shell，体验与 SSH 一致（cd/环境变量保持、全屏程序、
// Tab 补全、Ctrl-C）。终端面向控制台管理员，受登录会话保护；
// shell_allow/shell_deny 只约束单次执行（tool_exec 与 /api/exec），不适用于交互终端。
package term

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// Manager 管理交互终端会话。
type Manager struct {
	Enabled  bool
	ShellBin string // 留空自动取 $SHELL，再退回 /bin/bash
	MaxConns int    // 并发会话上限
	live     atomic.Int32
}

func New(enabled bool, shellBin string, maxConns int) *Manager {
	if maxConns <= 0 {
		maxConns = 8
	}
	if shellBin == "" {
		shellBin = os.Getenv("SHELL")
	}
	if shellBin == "" {
		shellBin = "/bin/bash"
	}
	return &Manager{Enabled: enabled, ShellBin: shellBin, MaxConns: maxConns}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	// gorilla 默认校验 Origin 与 Host 一致（同源），会话鉴权在 AuthGuard 完成
}

type resizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// ServeHTTP 处理一次 WebSocket 终端连接：升级、起 PTY shell、双向搬运。
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !m.Enabled {
		http.Error(w, "terminal disabled（config.json 的 shell_enabled=false）", http.StatusForbidden)
		return
	}
	if m.live.Add(1) > int32(m.MaxConns) {
		m.live.Add(-1)
		http.Error(w, fmt.Sprintf("并发终端已达上限 %d", m.MaxConns), http.StatusTooManyRequests)
		return
	}
	defer m.live.Add(-1)

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade 已写过错误响应
	}
	defer ws.Close()

	shell := exec.Command(m.ShellBin, "-l", "-i") // 登录态 + 交互，与 SSH 行为一致
	shell.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	ptmx, err := pty.Start(shell)
	if err != nil {
		_ = ws.WriteMessage(websocket.TextMessage,
			[]byte("\r\n[server-mcp] 启动 shell 失败: "+err.Error()+"\r\n"))
		return
	}
	defer func() {
		// pty.Start 使子进程成为会话首进程；按进程组杀，避免遗留子进程
		if shell.Process != nil {
			_ = syscall.Kill(-shell.Process.Pid, syscall.SIGKILL)
			_ = shell.Process.Release()
		}
		_ = ptmx.Close()
		_, _ = shell.Process.Wait()
	}()

	// 控制消息（resize）用文本帧，键盘输入用二进制帧
	done := make(chan struct{})
	go func() { // WS -> PTY
		defer close(done)
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage && len(data) > 0 && data[0] == '{' {
				var rm resizeMsg
				if json.Unmarshal(data, &rm); rm.Type == "resize" && rm.Cols > 0 && rm.Rows > 0 {
					_ = pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(rm.Cols), Rows: uint16(rm.Rows)})
					continue
				}
			}
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 32*1024)
	for { // PTY -> WS
		n, err := ptmx.Read(buf)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	select {
	case <-done:
	default:
		_ = ws.Close()
		<-done
	}
}
