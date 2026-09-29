package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"servermcp/internal/arthas"
	"servermcp/internal/audit"
	"servermcp/internal/auth"
	"servermcp/internal/config"
	"servermcp/internal/dbquery"
	"servermcp/internal/fsbrowse"
	"servermcp/internal/logsw"
	"servermcp/internal/shell"
	"servermcp/internal/sysinfo"
	"servermcp/internal/term"
)

// Server 汇总 web 层依赖。
type Server struct {
	Cfg    *config.Config
	Keys   *auth.KeyStore
	Sess   *auth.Sessions
	Shell  *shell.Runner
	Logs   *logsw.Manager
	DB     *dbquery.Querier
	Arthas *arthas.Manager
	FS     *fsbrowse.Manager
	Term   *term.Manager
	Audit  *audit.Logger
}

// ---- 小工具 ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体 JSON 无效: " + err.Error()})
		return false
	}
	return true
}

// Register 把全部路由挂到 mux。
func (s *Server) Register(mux *http.ServeMux, mcpHandler http.Handler, indexHTML []byte) {
	// 页面与健康检查
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// 控制台静态资源（xterm.js 等）
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(StaticFS())))
	// MCP streamable HTTP 端点
	mux.Handle("/mcp", mcpHandler)
	// 交互终端（WebSocket + PTY）
	mux.HandleFunc("/api/ws/term", s.Term.ServeHTTP)

	// ---- 鉴权 / 密钥管理 ----
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/authinfo", s.handleAuthInfo)
	mux.HandleFunc("GET /api/keys", s.handleKeysList)
	mux.HandleFunc("POST /api/keys", s.handleKeysCreate)
	mux.HandleFunc("PUT /api/keys/{id}", s.handleKeysUpdate)
	mux.HandleFunc("DELETE /api/keys/{id}", s.handleKeysDelete)

	// ---- 运维能力 ----
	mux.HandleFunc("GET /api/overview", s.handleOverview)
	mux.HandleFunc("GET /api/processes", s.handleProcesses)
	mux.HandleFunc("GET /api/ports", s.handlePorts)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/log", s.handleLog)
	mux.HandleFunc("GET /api/logsearch", s.handleLogSearch)
	mux.HandleFunc("POST /api/db", s.handleDB)
	mux.HandleFunc("POST /api/exec", s.handleExec)
	mux.HandleFunc("GET /api/fs", s.handleFSList)
	mux.HandleFunc("GET /api/fs/read", s.handleFSRead)
	mux.HandleFunc("GET /api/fs/download", s.handleFSDownload)
	mux.HandleFunc("GET /api/jvm", s.handleJVM)
	mux.HandleFunc("GET /api/arthas/status", s.handleArthasStatus)
	mux.HandleFunc("POST /api/arthas/attach", s.handleArthasAttach)
	mux.HandleFunc("POST /api/arthas/exec", s.handleArthasExec)
}

// ---- 鉴权 / 密钥管理 ----

func (s *Server) handleAuthInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"auth_required": s.Cfg.AdminPassword != ""})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !readBody(w, r, &body) {
		return
	}
	if s.Cfg.AdminPassword == "" {
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "控制台未启用密码（config.json 的 admin_password 为空）"})
		return
	}
	token := s.Sess.Verify(s.Cfg.AdminPassword, body.Password)
	if token == "" {
		time.Sleep(500 * time.Millisecond) // 减缓爆破
		s.Audit.Event("login_failed", "console", map[string]any{"remote": r.RemoteAddr})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "密码错误"})
		return
	}
	s.Audit.Event("login_ok", "console", map[string]any{"remote": r.RemoteAddr})
	// 会话同时下发 cookie：WebSocket（/api/ws/term）无法携带 Authorization 头
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   s.Cfg.SessionTTLH * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "ttl_h": s.Cfg.SessionTTLH})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.Sess.Delete(bearerToken(r.Header.Get("Authorization")))
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleKeysList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Keys.List())
}

func (s *Server) handleKeysCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name  string   `json:"name"`
		Tools []string `json:"tools"`
	}
	if !readBody(w, r, &body) {
		return
	}
	k, err := s.Keys.Create(body.Name, body.Tools)
	if err != nil {
		writeErr(w, err)
		return
	}
	// 审计只记名称与授权工具集，绝不记密钥明文
	s.Audit.Event("key_created", "console", map[string]any{"id": k.ID, "name": k.Name, "tools": k.Tools})
	writeJSON(w, http.StatusOK, k)
}

func (s *Server) handleKeysUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string   `json:"name"`
		Tools   []string `json:"tools"`
		Enabled *bool    `json:"enabled"`
	}
	if !readBody(w, r, &body) {
		return
	}
	k, err := s.Keys.Update(r.PathValue("id"), body.Name, body.Tools, body.Enabled)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.Audit.Event("key_updated", "console", map[string]any{
		"id": k.ID, "name": k.Name, "tools": k.Tools, "enabled": k.Enabled})
	writeJSON(w, http.StatusOK, k)
}

func (s *Server) handleKeysDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Keys.Delete(r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	s.Audit.Event("key_deleted", "console", map[string]any{"id": r.PathValue("id")})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- 运维能力 ----

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := sysinfo.GetOverview()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 20
	}
	writeJSON(w, http.StatusOK, sysinfo.Processes(r.URL.Query().Get("sort"), limit))
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	rows, err := sysinfo.ListeningPorts()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Logs.List())
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tail, _ := strconv.Atoi(q.Get("tail"))
	if tail == 0 {
		tail = 300
	}
	res, err := s.Logs.Read(q.Get("source"), tail, q.Get("grep"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleLogSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	res, err := s.Logs.Search(q.Get("source"), q.Get("grep"), limit, offset, q.Get("ci") == "1")
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDB(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SQL string `json:"sql"`
	}
	if !readBody(w, r, &body) {
		return
	}
	res, err := s.DB.Query(body.SQL)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Command string  `json:"command"`
		Timeout float64 `json:"timeout"`
		Cwd     string  `json:"cwd"`
	}
	if !readBody(w, r, &body) {
		return
	}
	// 管理员通道：跳过 allow/deny 名单（名单管 MCP 密钥侧），但记录审计
	res, err := s.Shell.RunAdmin(body.Command, body.Timeout, body.Cwd)
	entry := map[string]any{
		"command": body.Command, "timeout_s": body.Timeout,
		"cwd": body.Cwd, "remote": r.RemoteAddr,
	}
	if err != nil {
		entry["error"] = err.Error()
		s.Audit.Event("console_shell_exec", "console", entry)
		writeErr(w, err)
		return
	}
	entry["exit_code"] = res.ExitCode
	entry["timed_out"] = res.TimedOut
	entry["duration_s"] = res.DurationS
	s.Audit.Event("console_shell_exec", "console", entry)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleJVM(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, sysinfo.ListJVMs())
}

// ---- 文件浏览（只读） ----

func (s *Server) handleFSList(w http.ResponseWriter, r *http.Request) {
	res, err := s.FS.List(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleFSRead(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, err := s.FS.Read(q.Get("path"), q.Get("end") == "tail")
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleFSDownload(w http.ResponseWriter, r *http.Request) {
	rp, err := s.FS.ResolveForDownload(r.URL.Query().Get("path"))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Disposition",
		"attachment; filename*=UTF-8''"+url.PathEscape(filepath.Base(rp)))
	http.ServeFile(w, r, rp)
}

func (s *Server) handleArthasStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Arthas.Status())
}

func (s *Server) handleArthasAttach(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PID int `json:"pid"`
	}
	if !readBody(w, r, &body) {
		return
	}
	res, err := s.Arthas.Attach(body.PID)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.Audit.Event("arthas_attach", "console", map[string]any{"pid": body.PID})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleArthasExec(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Command string  `json:"command"`
		Timeout float64 `json:"timeout"`
	}
	if !readBody(w, r, &body) {
		return
	}
	out, err := s.Arthas.Exec(body.Command, body.Timeout)
	entry := map[string]any{"command": body.Command, "timeout_s": body.Timeout}
	if err != nil {
		entry["error"] = err.Error()
		s.Audit.Event("arthas_exec", "console", entry)
		writeErr(w, err)
		return
	}
	s.Audit.Event("arthas_exec", "console", entry)
	writeJSON(w, http.StatusOK, map[string]string{"output": out})
}
