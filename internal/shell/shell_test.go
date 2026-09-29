package shell

import (
	"strings"
	"testing"

	"servermcp/internal/config"
)

func newTestRunner(t *testing.T, enabled bool) *Runner {
	t.Helper()
	r, err := NewRunner(&config.Config{
		ShellEnabled:    enabled,
		ShellDeny:       []string{"forbidden"},
		ShellAllow:      []string{"^echo ", "^ls "},
		ShellTimeoutMax: 5,
		MaxOutput:       1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGuardAllowDeny(t *testing.T) {
	r := newTestRunner(t, true)

	if _, err := r.Run("echo forbidden", 5, ""); err == nil {
		t.Fatal("deny 黑名单应拒绝（优先于 allow）")
	}
	if _, err := r.Run("cat /etc/passwd", 5, ""); err == nil {
		t.Fatal("allow 外命令应拒绝")
	}
	if _, err := r.Run("", 5, ""); err == nil {
		t.Fatal("空命令应拒绝")
	}
}

func TestRunResult(t *testing.T) {
	r := newTestRunner(t, true)

	res, err := r.Run("echo hello", 5, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "hello\n" || res.ExitCode != 0 || res.TimedOut {
		t.Fatalf("结果错误: %+v", res)
	}

	res, err = r.Run("echo oops >&2; exit 3", 5, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || res.Stderr != "oops\n" {
		t.Fatalf("退出码/stderr 错误: %+v", res)
	}
}

func TestRunTimeoutKillsGroup(t *testing.T) {
	r := newTestRunner(t, true)
	res, err := r.RunAdmin("sleep 5 & wait", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.ExitCode != -9 {
		t.Fatalf("应超时被 SIGKILL: %+v", res)
	}
}

func TestRunAdminSkipsAllowDeny(t *testing.T) {
	r := newTestRunner(t, true)

	// Run 被名单拦，RunAdmin 放行——管理员通道语义
	if _, err := r.Run("cat /dev/null", 5, ""); err == nil {
		t.Fatal("allow 外命令 Run 应拒绝")
	}
	if _, err := r.Run("echo forbidden", 5, ""); err == nil {
		t.Fatal("deny 命中 Run 应拒绝")
	}
	if _, err := r.RunAdmin("cat /dev/null", 5, ""); err != nil {
		t.Fatalf("RunAdmin 应跳过 allow: %v", err)
	}
	if _, err := r.RunAdmin("echo forbidden", 5, ""); err != nil {
		t.Fatalf("RunAdmin 应跳过 deny: %v", err)
	}
}

func TestDisabled(t *testing.T) {
	r := newTestRunner(t, false)
	if _, err := r.Run("echo hi", 5, ""); err == nil {
		t.Fatal("shell_enabled=false 时 Run 应拒绝")
	}
	if _, err := r.RunAdmin("echo hi", 5, ""); err == nil {
		t.Fatal("shell_enabled=false 时 RunAdmin 应拒绝")
	}
}

func TestBadRegexRejected(t *testing.T) {
	if _, err := NewRunner(&config.Config{ShellDeny: []string{"("}}); err == nil {
		t.Fatal("非法正则应报错")
	}
	if _, err := NewRunner(&config.Config{ShellAllow: []string{"*"}}); err == nil {
		t.Fatal("非法 allow 正则应报错")
	}
}

func TestCwdValidation(t *testing.T) {
	r := newTestRunner(t, true)
	if _, err := r.RunAdmin("pwd", 5, "/nonexistent-dir-xyz"); err == nil {
		t.Fatal("不存在的工作目录应报错")
	}
	res, err := r.RunAdmin("pwd", 5, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "/tmp") {
		t.Fatalf("cwd 未生效: %q", res.Stdout)
	}
}
