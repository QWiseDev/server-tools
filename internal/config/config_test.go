package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDefaultsWhenMissing(t *testing.T) {
	cfg, where, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if where != "内置默认值" {
		t.Fatalf("where = %q", where)
	}
	if cfg.Port != 8808 || !cfg.ShellEnabled {
		t.Fatalf("默认值错误: %+v", cfg)
	}
	// 无配置文件时相对路径按 cwd 转绝对（落点即运行目录）
	if filepath.Base(cfg.KeysPath) != "keys.json" || !filepath.IsAbs(cfg.KeysPath) {
		t.Fatalf("keys_path 默认应为运行目录下的 keys.json: %q", cfg.KeysPath)
	}
	if len(cfg.FsRoots) != 1 || cfg.FsRoots[0] != "~" {
		t.Fatalf("fs_roots 默认应为 [~]: %+v", cfg.FsRoots)
	}
	if filepath.Base(cfg.AuditPath) != "audit.log" {
		t.Fatalf("audit_path 默认错误: %q", cfg.AuditPath)
	}
}

func TestLoadOverridesAndPathResolve(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	content := `{"port":9999,"keys_path":"k.json","admin_password":"x","log_files":["/var/log/*.log"]}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 9999 || cfg.AdminPassword != "x" {
		t.Fatalf("覆盖失败: %+v", cfg)
	}
	// 相对 keys_path 按词法拼接在配置文件所在目录（JoinDir 不解析软链，落点一致）
	if cfg.KeysPath != filepath.Join(Dir(p), "k.json") {
		t.Fatalf("keys_path 应解析到配置目录: %q", cfg.KeysPath)
	}
	// log_files 提供了值，不保留默认；未提供的 fs_roots 保留默认
	if len(cfg.FsRoots) != 1 {
		t.Fatalf("未提供的字段应保留默认: %+v", cfg.FsRoots)
	}
}

func TestLoadBrokenJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "解析配置") {
		t.Fatalf("坏 JSON 应报错: %v", err)
	}
}

func TestJoinDir(t *testing.T) {
	if got := JoinDir("/opt/x", "k.json"); got != "/opt/x/k.json" {
		t.Fatalf("JoinDir = %q", got)
	}
	if got := JoinDir("/opt/x", "/abs/k.json"); got != "/abs/k.json" {
		t.Fatalf("绝对路径应原样: %q", got)
	}
	if got := JoinDir("", "rel.json"); !filepath.IsAbs(got) {
		t.Fatalf("空 base 应按 cwd 转绝对: %q", got)
	}
	if got := JoinDir("/opt/x", ""); got != "" {
		t.Fatalf("空 p 应返回空: %q", got)
	}
}
