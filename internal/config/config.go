// Package config 负责 server-mcp 的配置加载：config.json + 内置默认值。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config 是 config.json 的全部字段；未填写的字段使用默认值。
type Config struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	AdminPassword string `json:"admin_password"` // Web 控制台登录密码；空 = 控制台免登录
	KeysPath      string `json:"keys_path"`      // MCP 密钥存储；相对路径基于配置文件所在目录
	AuditPath     string `json:"audit_path"`     // 审计日志（JSON 行）；空 = 关闭审计
	SessionTTLH   int    `json:"session_ttl_h"`  // 控制台会话有效期（小时）

	DBPath           string   `json:"db_path"`  // SQLite；留空关闭查询能力
	FsRoots          []string `json:"fs_roots"` // 文件浏览白名单根目录（~ 表示用户主目录）
	LogFiles         []string `json:"log_files"`
	LogDirs          []string `json:"log_dirs"`
	DockerContainers []string `json:"docker_containers"`

	ArthasHome       string `json:"arthas_home"`
	ArthasTelnetPort int    `json:"arthas_telnet_port"`
	ArthasHTTPPort   int    `json:"arthas_http_port"`
	JavaBin          string `json:"java_bin"`

	MaxOutput int `json:"max_output"` // 单次返回文本截断长度（字节）

	ShellEnabled    bool     `json:"shell_enabled"`
	ShellAllow      []string `json:"shell_allow"` // 非空时命令须命中其一（正则）
	ShellDeny       []string `json:"shell_deny"`  // 命中任一即拒绝（优先级最高）
	ShellTimeoutMax int      `json:"shell_timeout_max"`
	ShellCwd        string   `json:"shell_cwd"`
}

// Defaults 返回一份默认配置。
func Defaults() Config {
	return Config{
		Host:             "127.0.0.1",
		Port:             8808,
		KeysPath:         "keys.json",
		AuditPath:        "audit.log",
		SessionTTLH:      168,
		FsRoots:          []string{"~"},
		LogFiles:         []string{},
		LogDirs:          []string{},
		DockerContainers: []string{},
		ArthasTelnetPort: 3658,
		ArthasHTTPPort:   8563,
		MaxOutput:        20000,
		ShellEnabled:     true,
		ShellAllow:       []string{},
		ShellDeny:        []string{},
		ShellTimeoutMax:  300,
	}
}

// Load 读取配置文件（JSON），未提供的字段保持默认值。
// keys_path / audit_path 相对路径基于配置文件所在目录解析。
func Load(path string) (*Config, string, error) {
	cfg := Defaults()
	where := "内置默认值"
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("读取配置 %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, "", fmt.Errorf("解析配置 %s: %w", path, err)
		}
		where = path
	}
	if cfg.KeysPath != "" && !filepath.IsAbs(cfg.KeysPath) {
		cfg.KeysPath = JoinDir(Dir(path), cfg.KeysPath)
	}
	if cfg.AuditPath != "" && !filepath.IsAbs(cfg.AuditPath) {
		cfg.AuditPath = JoinDir(Dir(path), cfg.AuditPath)
	}
	return &cfg, where, nil
}
