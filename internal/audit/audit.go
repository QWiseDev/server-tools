// Package audit 提供追加式 JSON 行审计日志：谁（actor）在何时做了什么。
// 面向服务器运维工具的核心可追溯性：shell 执行、终端会话、密钥管理、
// 登录成败。审计路径留空时为 no-op。绝不记录密码与密钥明文。
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Logger 线程安全；零值与 path 为空时均为 no-op，调用方无需判空。
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// New 打开审计日志（追加，0600）。path 为空返回 no-op logger。
func New(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

// Event 记录一条审计事件。kv 可为 nil，值须可 JSON 序列化。
func (l *Logger) Event(event, actor string, kv map[string]any) {
	if l == nil || l.f == nil {
		return
	}
	rec := map[string]any{
		"ts":    time.Now().Format("2006-01-02 15:04:05"),
		"event": event,
		"actor": actor,
	}
	for k, v := range kv {
		if v == nil {
			continue
		}
		rec[k] = v
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}
