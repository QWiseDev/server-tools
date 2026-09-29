// Package shell 提供带超时与白/黑名单约束的 shell 命令执行。
//
// 安全模型：
//   - 命令以 /bin/bash -lc 执行（登录 shell，继承 PATH）
//   - start_new_session：整组进程在超时后一起 SIGKILL，不留孤儿
//   - shell_deny 黑名单正则优先；shell_allow 非空时命令须命中其一
//   - 名单只是绊线而非沙箱，真正的信任边界是网络绑定 + 管理密码
package shell

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"servermcp/internal/config"
	"servermcp/internal/textutil"
)

// Result 是一次命令执行的完整结果。
type Result struct {
	Command   string  `json:"command"`
	ExitCode  int     `json:"exit_code"` // 被信号杀死时为负值（如 -9）
	TimedOut  bool    `json:"timed_out"`
	DurationS float64 `json:"duration_s"`
	Stdout    string  `json:"stdout"`
	Stderr    string  `json:"stderr"`
}

// Runner 持有 shell 执行约束。goroutine 安全（字段只读）。
type Runner struct {
	enabled    bool
	allow      []*regexp.Regexp
	deny       []*regexp.Regexp
	timeoutMax time.Duration
	defaultCwd string
	maxOutput  int
}

func NewRunner(cfg *config.Config) (*Runner, error) {
	r := &Runner{
		enabled:    cfg.ShellEnabled,
		timeoutMax: time.Duration(cfg.ShellTimeoutMax) * time.Second,
		defaultCwd: cfg.ShellCwd,
		maxOutput:  cfg.MaxOutput,
	}
	if r.timeoutMax <= 0 {
		r.timeoutMax = 300 * time.Second
	}
	compile := func(pats []string) ([]*regexp.Regexp, error) {
		var out []*regexp.Regexp
		for _, p := range pats {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("编译正则 %q: %w", p, err)
			}
			out = append(out, re)
		}
		return out, nil
	}
	var err error
	if r.deny, err = compile(cfg.ShellDeny); err != nil {
		return nil, err
	}
	if r.allow, err = compile(cfg.ShellAllow); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Runner) guard(command string) error {
	if !r.enabled {
		return fmt.Errorf("shell 执行已关闭（config.json 的 shell_enabled）")
	}
	if command == "" {
		return fmt.Errorf("命令为空")
	}
	for _, re := range r.deny {
		if re.MatchString(command) {
			return fmt.Errorf("命令命中 shell_deny 黑名单：/%s/", re.String())
		}
	}
	if len(r.allow) > 0 {
		ok := false
		for _, re := range r.allow {
			if re.MatchString(command) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("命令不在 shell_allow 白名单内（config.json 的 shell_allow）")
		}
	}
	return nil
}

// Run 执行 command（走 allow/deny 名单约束，MCP 密钥通道使用）。
// timeoutSeconds<=0 时用默认 60s，超出上限则被钳制。
// cwd 为空时用 Runner 默认目录，再为空则继承服务进程目录。
func (r *Runner) Run(command string, timeoutSeconds float64, cwd string) (*Result, error) {
	if err := r.guard(command); err != nil {
		return nil, err
	}
	return r.exec(command, timeoutSeconds, cwd)
}

// RunAdmin 跳过 allow/deny 名单，仅供控制台管理员通道（/api/exec）使用：
// 管理员已通过密码鉴权，且交互终端本就不受名单约束——名单是给 MCP
// 密钥（agent）设的绊线，不该拦住控制台本人。shell_enabled 仍然生效。
func (r *Runner) RunAdmin(command string, timeoutSeconds float64, cwd string) (*Result, error) {
	if !r.enabled {
		return nil, fmt.Errorf("shell 执行已关闭（config.json 的 shell_enabled）")
	}
	if command == "" {
		return nil, fmt.Errorf("命令为空")
	}
	return r.exec(command, timeoutSeconds, cwd)
}

func (r *Runner) exec(command string, timeoutSeconds float64, cwd string) (*Result, error) {
	timeout := 60 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds * float64(time.Second))
	}
	if timeout > r.timeoutMax {
		timeout = r.timeoutMax
	}
	if timeout < time.Second {
		timeout = time.Second
	}

	workdir := cwd
	if workdir == "" {
		workdir = r.defaultCwd
	}
	if workdir != "" {
		abs, err := filepath.Abs(workdir)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(abs)
		if err != nil || !st.IsDir() {
			return nil, fmt.Errorf("工作目录不存在: %s", workdir)
		}
		workdir = abs
	} else {
		workdir = ""
	}

	start := time.Now()
	cmd := exec.Command("/bin/bash", "-lc", command)
	cmd.Dir = workdir
	// Setpgid 让 bash 及其全部子进程独立成组，超时可整组 SIGKILL
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动命令失败: %w", err)
	}

	outCh := make(chan []byte, 1)
	errCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(stdout)
		outCh <- b
	}()
	go func() {
		b, _ := io.ReadAll(stderr)
		errCh <- b
	}()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timedOut := false
	select {
	case <-done:
	case <-time.After(timeout):
		timedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	stdoutBytes, stderrBytes := <-outCh, <-errCh

	res := &Result{
		Command:   command,
		ExitCode:  exitStatus(cmd.ProcessState),
		TimedOut:  timedOut,
		DurationS: time.Since(start).Seconds(),
		Stdout:    textutil.Clip(string(stdoutBytes), r.maxOutput),
		Stderr:    textutil.Clip(string(stderrBytes), r.maxOutput),
	}
	return res, nil
}

// exitStatus 提取退出码：正常退出返回退出值；被信号杀死返回负信号数（如 -9）。
func exitStatus(ps *os.ProcessState) int {
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok {
		return -1
	}
	if ws.Signaled() {
		return -int(ws.Signal())
	}
	return ws.ExitStatus()
}
