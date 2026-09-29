package config

import (
	"path/filepath"
	"strings"
)

// Dir 返回 path 的目录；path 为空（未指定配置文件）时返回当前目录。
func Dir(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Dir(path)
}

// JoinDir 以 base（可为空）为基准解析 p 的绝对路径。
func JoinDir(base, p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	if base == "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return abs
	}
	// 处理形如 /opt/x/../y 的拼接
	return filepath.Clean(strings.TrimRight(base, "/") + "/" + p)
}
