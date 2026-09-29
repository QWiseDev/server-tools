// Package web 提供 HTTP 层：路由、鉴权中间件、JSON API 与内嵌控制台页面。
package web

import (
	"net/http"
	"strings"

	"servermcp/internal/auth"
	"servermcp/internal/config"
)

// bearerToken 从 Authorization 头解析 Bearer 值。
func bearerToken(h string) string {
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(tok)
}

// sessionCookie 是控制台会话 cookie：浏览器 WebSocket 无法携带
// Authorization 头，靠它完成 /api/ws/term 的会话鉴权。
const sessionCookie = "smcp_session"

// AuthGuard 是全局鉴权中间件：
//   - / 与 /healthz 与 /api/login、/api/authinfo 豁免
//   - /mcp     需要 MCP 密钥（Authorization: Bearer sk-...，且未停用）
//   - /api/*   需要控制台登录会话（Authorization 头或 smcp_session cookie）；
//     admin_password 为空则免登录
func AuthGuard(cfg *config.Config, keys *auth.KeyStore, sess *auth.Sessions) func(http.Handler) http.Handler {
	exempt := map[string]bool{"/": true, "/healthz": true, "/api/login": true, "/api/authinfo": true}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case exempt[p] || strings.HasPrefix(p, "/static/"):
				next.ServeHTTP(w, r)
			case p == "/mcp" || strings.HasPrefix(p, "/mcp/"):
				key := keys.GetByKey(bearerToken(r.Header.Get("Authorization")))
				if key == nil {
					http.Error(w, "unauthorized: 无效或已停用的 MCP 密钥", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			case strings.HasPrefix(p, "/api"):
				if cfg.AdminPassword != "" {
					tok := bearerToken(r.Header.Get("Authorization"))
					if tok == "" {
						if c, err := r.Cookie(sessionCookie); err == nil {
							tok = c.Value
						}
					}
					if !sess.Check(tok) {
						http.Error(w, "unauthorized: 请先登录", http.StatusUnauthorized)
						return
					}
				}
				next.ServeHTTP(w, r)
			default:
				http.NotFound(w, r)
			}
		})
	}
}
