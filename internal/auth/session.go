// Package auth 提供两类凭证：Web 控制台密码会话（session）与 MCP 接入密钥（keys）。
package auth

import (
	"crypto/subtle"
	"sync"
	"time"
)

// Sessions 是内存态的登录会话表：token -> 过期时间。服务重启后需重新登录。
type Sessions struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{m: map[string]time.Time{}, ttl: ttl}
}

// Verify 校验密码；正确则创建会话并返回 token，错误返回空串。
// 使用恒定时间比较，并在失败时由调用方决定是否延迟。
func (s *Sessions) Verify(password, input string) string {
	if password == "" || subtle.ConstantTimeCompare([]byte(password), []byte(input)) != 1 {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for t, exp := range s.m {
		if exp.Before(now) {
			delete(s.m, t)
		}
	}
	tok := randomToken()
	s.m[tok] = now.Add(s.ttl)
	return tok
}

func (s *Sessions) Check(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[token]
	if !ok {
		return false
	}
	if exp.Before(time.Now()) {
		delete(s.m, token)
		return false
	}
	return true
}

func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}
