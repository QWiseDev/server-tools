package arthas

import (
	"archive/zip"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"servermcp/internal/config"
	"servermcp/internal/textutil"
)

// 只开放只读排查命令；ognl/redefine/mc 可改字节码、stop/shutdown 会卸载 agent
var forbidden = map[string]bool{
	"ognl": true, "redefine": true, "mc": true, "stop": true,
	"shutdown": true, "exit": true, "quit": true,
}

var (
	trailingPrompt = regexp.MustCompile(`\[arthas@\d+$`)
	javaHomeRe     = regexp.MustCompile(`java\.home = (.+)`)
	mainClassRe    = regexp.MustCompile(`Main-Class:\s*(\S+)`)
	ansiRe         = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]|\x1b\\][^\x07]*\x07")
)

// Manager 管理 Arthas 安装发现、attach 与命令执行。
type Manager struct {
	cfg       *config.Config
	attachLog string

	mu          sync.Mutex
	attachedPID int // 我方 attach 的目标 pid（参考值）
}

func New(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg, attachLog: filepath.Join(Dir(cfg.ArthasHome), "arthas-attach.log")}
}

// Dir 返回 path 的目录；空则返回当前目录。
func Dir(p string) string {
	if p == "" {
		return "."
	}
	return filepath.Dir(p)
}

func expand(p string) string {
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

func (m *Manager) javaBin() string {
	if m.cfg.JavaBin != "" {
		return m.cfg.JavaBin
	}
	if p, err := exec.LookPath("java"); err == nil {
		return p
	}
	return "java"
}

func portOpen(port int, host string, timeout time.Duration) bool {
	if host == "" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// arthasDir 找到含 arthas-core.jar / arthas-agent.jar 的目录。
func (m *Manager) arthasDir() string {
	var cands []string
	if m.cfg.ArthasHome != "" {
		cands = append(cands, expand(m.cfg.ArthasHome))
	}
	if home, err := os.UserHomeDir(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(home, ".arthas", "lib", "*", "arthas"))
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		cands = append(cands, matches...)
	}
	for _, d := range cands {
		if fileExists(filepath.Join(d, "arthas-core.jar")) &&
			fileExists(filepath.Join(d, "arthas-agent.jar")) {
			return d
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// StatusResult 是 arthas_status 的输出。
type StatusResult struct {
	Installed   bool   `json:"installed"`
	ArthasHome  string `json:"arthas_home"`
	Attached    bool   `json:"attached"`
	AttachedPID int    `json:"attached_pid"`
	ConsoleURL  string `json:"console_url"`
	AttachLog   string `json:"attach_log"`
}

// Status 返回安装/attach 状态。
func (m *Manager) Status() *StatusResult {
	d := m.arthasDir()
	m.mu.Lock()
	lastPID := m.attachedPID
	m.mu.Unlock()
	st := &StatusResult{
		Installed:   d != "",
		ArthasHome:  d,
		Attached:    portOpen(m.cfg.ArthasTelnetPort, "127.0.0.1", 500*time.Millisecond),
		ConsoleURL:  fmt.Sprintf("http://<server-host>:%d/", m.cfg.ArthasHTTPPort),
		AttachedPID: lastPID,
	}
	if !st.Attached {
		st.AttachedPID = 0
	}
	if data, err := os.ReadFile(m.attachLog); err == nil {
		st.AttachLog = textutil.Clip(string(data), 1500)
	}
	return st
}

// javaHome 通过 java -XshowSettings 反查真实 JAVA_HOME（/usr/bin/java 是转发桩）。
func (m *Manager) javaHome() string {
	out, err := exec.Command(m.javaBin(), "-XshowSettings:properties", "-version").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "java.home") {
		return ""
	}
	if match := javaHomeRe.FindStringSubmatch(string(out)); match != nil {
		return strings.TrimSpace(match[1])
	}
	return ""
}

// toolsJarCandidates JDK8 的 attach API 在 tools.jar；java.home 可能是 <JDK>/jre。
func (m *Manager) toolsJarCandidates() []string {
	jh := m.javaHome()
	if jh == "" {
		return nil
	}
	var cands []string
	for _, p := range []string{
		filepath.Join(jh, "lib", "tools.jar"),
		filepath.Join(filepath.Dir(jh), "lib", "tools.jar"),
	} {
		dup := false
		for _, c := range cands {
			if c == p {
				dup = true
			}
		}
		if !dup {
			cands = append(cands, p)
		}
	}
	return cands
}

// coreMainClass 从 arthas-core.jar 的 Manifest 读主类
// （3.x 为 ...server.ArthasCore，4.x 为 ...core.Arthas）。
func coreMainClass(dir string) string {
	zr, err := zip.OpenReader(filepath.Join(dir, "arthas-core.jar"))
	if err == nil {
		defer zr.Close()
		for _, f := range zr.File {
			if f.Name != "META-INF/MANIFEST.MF" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				break
			}
			buf := make([]byte, 65536)
			n, _ := rc.Read(buf)
			rc.Close()
			if match := mainClassRe.FindStringSubmatch(string(buf[:n])); match != nil {
				return match[1]
			}
			break
		}
	}
	return "com.taobao.arthas.core.Arthas"
}

// AttachResult 是 attach 的输出。
type AttachResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	PID     int    `json:"pid"`
}

// Attach 把 Arthas agent attach 到指定 JVM pid（幂等：已 attach 则直接复用）。
func (m *Manager) Attach(pid int) (*AttachResult, error) {
	d := m.arthasDir()
	if d == "" {
		return nil, fmt.Errorf("未找到 Arthas 安装目录：配置 arthas_home，或先 " +
			"`java -jar arthas-boot.jar` 安装一次（默认装到 ~/.arthas/lib/）")
	}
	if portOpen(m.cfg.ArthasTelnetPort, "127.0.0.1", 500*time.Millisecond) {
		m.mu.Lock()
		lastPID := m.attachedPID
		m.mu.Unlock()
		return &AttachResult{OK: true,
			Message: fmt.Sprintf("已有 Arthas agent 在监听 %d，直接使用", m.cfg.ArthasTelnetPort),
			PID:     lastPID}, nil
	}

	common := []string{
		"-target-ip", "127.0.0.1",
		"-telnet-port", strconv.Itoa(m.cfg.ArthasTelnetPort),
		"-http-port", strconv.Itoa(m.cfg.ArthasHTTPPort),
		"-core", filepath.Join(d, "arthas-core.jar"),
		"-agent", filepath.Join(d, "arthas-agent.jar"),
	}
	var cmd *exec.Cmd
	tools := ""
	for _, c := range m.toolsJarCandidates() {
		if fileExists(c) {
			tools = c
			break
		}
	}
	if tools != "" {
		// JDK 8：attach API 在 tools.jar 里，java -jar 不吃 CLASSPATH，走 -cp + 主类
		cp := fmt.Sprintf("%s:%s", filepath.Join(d, "arthas-core.jar"), tools)
		cmd = exec.Command(m.javaBin(), "-Xms128M", "-Xmx128M", "-cp", cp,
			coreMainClass(d), "-pid", strconv.Itoa(pid))
		cmd.Args = append(cmd.Args, common...)
	} else {
		cmd = exec.Command(m.javaBin(), "-Xms128M", "-Xmx128M",
			"-jar", filepath.Join(d, "arthas-core.jar"), "-pid", strconv.Itoa(pid))
		cmd.Args = append(cmd.Args, common...)
	}
	cmd.Dir = d
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // 对应 start_new_session

	lf, err := os.Create(m.attachLog)
	if err != nil {
		return nil, fmt.Errorf("写 attach 日志失败: %w", err)
	}
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, fmt.Errorf("启动 arthas-core 失败: %w", err)
	}

	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if portOpen(m.cfg.ArthasTelnetPort, "127.0.0.1", 500*time.Millisecond) {
			lf.Close()
			m.mu.Lock()
			m.attachedPID = pid
			m.mu.Unlock()
			return &AttachResult{OK: true,
				Message: fmt.Sprintf("attach 成功，agent 已监听 telnet:%d / web:%d",
					m.cfg.ArthasTelnetPort, m.cfg.ArthasHTTPPort),
				PID: pid}, nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			lf.Close()
			return nil, fmt.Errorf("attach 进程退出: %s", logTail(m.attachLog, 1500))
		}
		time.Sleep(time.Second)
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	lf.Close()
	return nil, fmt.Errorf("attach 超时（40s）：%s", logTail(m.attachLog, 1500))
}

func logTail(path string, max int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(无日志)"
	}
	return textutil.Clip(string(data), max)
}

// Exec 执行 Arthas 只读排查命令并返回输出。
func (m *Manager) Exec(command string, timeoutSeconds float64) (string, error) {
	c := strings.TrimSpace(command)
	if c == "" {
		return "", fmt.Errorf("命令为空")
	}
	head := strings.ToLower(c)
	if i := strings.IndexAny(head, " \t"); i >= 0 {
		head = head[:i]
	}
	if forbidden[head] {
		return "", fmt.Errorf("禁止执行 %s（仅开放只读排查命令，写操作请人工在控制台进行）", head)
	}
	if !portOpen(m.cfg.ArthasTelnetPort, "127.0.0.1", 500*time.Millisecond) {
		return "", fmt.Errorf("Arthas agent 未 attach：先调 tool_list_jvms + tool_arthas_attach")
	}
	timeout := 30 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds * float64(time.Second))
	}
	if timeout > 120*time.Second {
		timeout = 120 * time.Second
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.ArthasTelnetPort))
	out, err := telnetCommand(addr, c, timeout)
	if err != nil {
		return "", err
	}
	return textutil.Clip(out, m.cfg.MaxOutput), nil
}
