// Package logsw 提供白名单约束下的日志读取：文件/glob/目录前缀 + Docker 容器。
package logsw

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"servermcp/internal/config"
	"servermcp/internal/textutil"
)

// FileRow 是一个可读日志源。
type FileRow struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mtime string `json:"mtime"`
}

// Snapshot 是 list_logs 的结果。
type Snapshot struct {
	Files      []FileRow `json:"files"`
	Containers []string  `json:"containers"`
}

// ReadResult 是 tail_log 的结果。
type ReadResult struct {
	Source string `json:"source"`
	Via    string `json:"via"`
	Count  int    `json:"count"`
	Text   string `json:"text"`
}

// Manager 持有日志白名单。goroutine 安全（字段只读）。
type Manager struct {
	files      []string // glob 模式
	dirs       []string // 目录前缀
	containers []string
	dockerBin  string
	maxOutput  int
}

func NewManager(cfg *config.Config) *Manager {
	docker, _ := exec.LookPath("docker")
	return &Manager{
		files:      cfg.LogFiles,
		dirs:       cfg.LogDirs,
		containers: cfg.DockerContainers,
		dockerBin:  docker,
		maxOutput:  cfg.MaxOutput,
	}
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

// List 汇总白名单内全部日志文件。
func (m *Manager) List() *Snapshot {
	var out []FileRow
	seen := map[string]bool{}
	for _, pat := range m.files {
		matches, _ := filepath.Glob(expand(pat))
		sort.Strings(matches)
		for _, f := range matches {
			rp, err := filepath.EvalSymlinks(f)
			if err != nil {
				rp = f
			}
			if seen[rp] {
				continue
			}
			st, err := os.Stat(rp)
			if err != nil || st.IsDir() {
				continue
			}
			seen[rp] = true
			out = append(out, FileRow{
				Path:  rp,
				Size:  st.Size(),
				Mtime: st.ModTime().Format("01-02 15:04"),
			})
		}
	}
	return &Snapshot{
		Files:      out,
		Containers: append([]string{}, m.containers...),
	}
}

// allowed 解析并校验文件路径是否在白名单内。
func (m *Manager) allowed(source string) (string, error) {
	rp, err := filepath.Abs(expand(source))
	if err != nil {
		return "", err
	}
	if rp2, err2 := filepath.EvalSymlinks(rp); err2 == nil {
		rp = rp2
	}
	for _, f := range m.List().Files {
		if f.Path == rp {
			return rp, nil
		}
	}
	for _, d := range m.dirs {
		base, err := filepath.Abs(expand(d))
		if err != nil {
			continue
		}
		if strings.HasPrefix(rp, base+string(filepath.Separator)) {
			return rp, nil
		}
	}
	return "", fmt.Errorf("%s 不在日志白名单内（config.json 的 log_files/log_dirs）", source)
}

// Read 读取日志：source 可为文件路径（须在白名单内）或 "docker:容器名"。
// tail 限制行数（1..5000），grep 支持子串或 /正则/。
func (m *Manager) Read(source string, tail int, grep string) (*ReadResult, error) {
	if tail < 1 {
		tail = 1
	}
	if tail > 5000 {
		tail = 5000
	}
	var lines []string
	var via string
	if rest, ok := strings.CutPrefix(source, "docker:"); ok {
		c := strings.TrimSpace(rest)
		if !contains(m.containers, c) {
			return nil, fmt.Errorf("容器 %s 不在白名单内（config.json 的 docker_containers）", c)
		}
		if m.dockerBin == "" {
			return nil, fmt.Errorf("未找到 docker 命令")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, m.dockerBin, "logs", "--tail", fmt.Sprint(tail), c).CombinedOutput()
		if err != nil && len(out) == 0 {
			return nil, fmt.Errorf("docker logs 失败: %v", err)
		}
		lines = splitLines(string(out))
		via = "docker logs"
	} else {
		rp, err := m.allowed(source)
		if err != nil {
			return nil, err
		}
		lines = tailLines(rp, tail)
		via = "file tail"
	}
	lines = filterLines(lines, grep)
	return &ReadResult{
		Source: source,
		Via:    via,
		Count:  len(lines),
		Text:   textutil.Clip(strings.Join(lines, "\n"), m.maxOutput),
	}, nil
}

// ---- 内部工具 ----

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

// tailLines 从文件末尾最多读 4MB，取最后 n 行。
func tailLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("打开文件失败: %v", err)}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return []string{fmt.Sprintf("读取文件信息失败: %v", err)}
	}
	const maxBytes = 4_000_000
	size := st.Size()
	read := int64(0)
	var data []byte
	for read < maxBytes && read < size && bytes.Count(data, []byte{'\n'}) <= n {
		step := int64(65536)
		if size-read < step {
			step = size - read
		}
		buf := make([]byte, step)
		if _, err := f.ReadAt(buf, size-read-step); err != nil {
			break
		}
		data = append(buf, data...)
		read += step
	}
	lines := splitLines(string(data))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// filterLines：grep 为空原样返回；/.../ 形式按正则，否则按子串。
func filterLines(lines []string, grep string) []string {
	if grep == "" {
		return lines
	}
	if len(grep) > 2 && strings.HasPrefix(grep, "/") && strings.HasSuffix(grep, "/") {
		re, err := regexp.Compile(grep[1 : len(grep)-1])
		if err != nil {
			return []string{fmt.Sprintf("正则无效: %v", err)}
		}
		var out []string
		for _, l := range lines {
			if re.MatchString(l) {
				out = append(out, l)
			}
		}
		return out
	}
	var out []string
	for _, l := range lines {
		if strings.Contains(l, grep) {
			out = append(out, l)
		}
	}
	return out
}
