// Package fsbrowse 提供白名单根目录约束下的只读文件浏览：
// 目录列表、文本预览（头/尾）、下载。所有路径先做 realpath 解析，
// 再强制落在某个根目录内，防穿越与软链逃逸。写操作请走 shell。
package fsbrowse

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	previewLimit = 256 * 1024 // 预览最多读取的字节数
	binaryProbe  = 8000       // 二进制探测：前 8KB 出现 NUL 即判定
)

// Entry 是目录里的一项。
type Entry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mtime string `json:"mtime"`
	IsDir bool   `json:"is_dir"`
}

// Listing 是一次目录浏览的结果。
type Listing struct {
	Path    string  `json:"path"`   // 当前目录；"" 表示根视图
	Parent  string  `json:"parent"` // 上级；根视图为 ""
	Entries []Entry `json:"entries"`
}

// Preview 是一次文件预览的结果。
type Preview struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary"`
	Content   string `json:"content"`
}

// Manager 持有允许浏览的根目录清单。goroutine 安全。
type Manager struct {
	roots []string // 原始配置值（支持 ~）
}

func New(roots []string) *Manager {
	return &Manager{roots: append([]string{}, roots...)}
}

func expand(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// resolvedRoots 实时解析根目录（realpath），跳过不存在的。
func (m *Manager) resolvedRoots() []string {
	var out []string
	for _, r := range m.roots {
		abs, err := filepath.Abs(expand(r))
		if err != nil {
			continue
		}
		if rp, err := filepath.EvalSymlinks(abs); err == nil {
			out = append(out, rp)
		} else {
			out = append(out, abs)
		}
	}
	return out
}

// resolve 校验 path 在某个根目录内，返回 realpath。
func (m *Manager) resolve(path string) (string, error) {
	if len(m.roots) == 0 {
		return "", fmt.Errorf("fs_roots 为空，文件浏览已关闭（config.json）")
	}
	abs, err := filepath.Abs(expand(path))
	if err != nil {
		return "", err
	}
	rp, err := filepath.EvalSymlinks(abs) // 软链在此被解析为真实目标
	if err != nil {
		return "", fmt.Errorf("路径不存在或不可达: %s", path)
	}
	rp = filepath.Clean(rp)
	for _, root := range m.resolvedRoots() {
		if rp == root {
			return rp, nil
		}
		if strings.HasPrefix(rp, root+string(filepath.Separator)) {
			return rp, nil
		}
	}
	return "", fmt.Errorf("%s 不在文件浏览白名单内（config.json 的 fs_roots）", path)
}

// List 浏览目录。path 为空时返回根视图（每个根目录一项）。
func (m *Manager) List(path string) (*Listing, error) {
	if strings.TrimSpace(path) == "" {
		out := &Listing{}
		for _, display := range m.roots {
			rp, err := m.resolve(display)
			if err != nil {
				continue
			}
			st, err := os.Stat(rp)
			if err != nil || !st.IsDir() {
				continue
			}
			out.Entries = append(out.Entries, Entry{
				Name:  display,
				Path:  rp,
				Mtime: st.ModTime().Format("01-02 15:04"),
				IsDir: true,
			})
		}
		return out, nil
	}

	rp, err := m.resolve(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(rp)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("不是目录: %s", path)
	}
	out := &Listing{Path: rp}
	// 根目录自身的上级是根视图；其余为文件系统上级
	isRoot := false
	for _, root := range m.resolvedRoots() {
		if rp == root {
			isRoot = true
			break
		}
	}
	if !isRoot {
		out.Parent = filepath.Dir(rp)
	}
	dirents, err := os.ReadDir(rp)
	if err != nil {
		return nil, err
	}
	for _, de := range dirents {
		entryPath := filepath.Join(rp, de.Name())
		var size int64
		var mtime time.Time
		if info, err := de.Info(); err == nil {
			size = info.Size()
			mtime = info.ModTime()
		}
		out.Entries = append(out.Entries, Entry{
			Name:  de.Name(),
			Path:  entryPath,
			Size:  size,
			Mtime: mtime.Format("01-02 15:04"),
			IsDir: de.IsDir(),
		})
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		ei, ej := out.Entries[i], out.Entries[j]
		if ei.IsDir != ej.IsDir {
			return ei.IsDir
		}
		return strings.ToLower(ei.Name) < strings.ToLower(ej.Name)
	})
	return out, nil
}

// Read 预览文件内容。tail=true 读末尾 previewLimit 字节，否则读开头。
func (m *Manager) Read(path string, tail bool) (*Preview, error) {
	rp, err := m.resolve(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(rp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("是目录，不能预览: %s", path)
	}
	out := &Preview{Path: rp, Size: st.Size()}

	var data []byte
	switch {
	case st.Size() <= previewLimit:
		data, err = io.ReadAll(f)
		out.Truncated = false
	case tail:
		if _, err := f.Seek(st.Size()-previewLimit, io.SeekStart); err != nil {
			return nil, err
		}
		data, err = io.ReadAll(f)
		out.Truncated = st.Size() > previewLimit
	default:
		data = make([]byte, previewLimit)
		n, rerr := io.ReadFull(f, data)
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			return nil, rerr
		}
		data = data[:n]
		out.Truncated = true
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	if bytes.IndexByte(data[:min(len(data), binaryProbe)], 0) >= 0 {
		out.Binary = true
		out.Content = fmt.Sprintf("(二进制文件，%d 字节，不预览；可下载后查看)", st.Size())
		return out, nil
	}
	out.Content = strings.ToValidUTF8(string(data), "\uFFFD")
	return out, nil
}

// ResolveForDownload 校验并返回可用于流式下载的真实文件路径。
func (m *Manager) ResolveForDownload(path string) (string, error) {
	rp, err := m.resolve(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(rp)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", fmt.Errorf("是目录，不能下载: %s", path)
	}
	return rp, nil
}
