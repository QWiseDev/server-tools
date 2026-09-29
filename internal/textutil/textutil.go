// Package textutil 提供输出截断等小工具。
package textutil

import (
	"unicode/utf8"
)

// Clip 保留字符串末尾最多 max 字节，并在 UTF-8 边界处截齐（避免截出半个汉字）。
// max <= 0 时原样返回。
func Clip(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	tail := s[len(s)-max:]
	for len(tail) > 0 && !utf8.ValidString(tail) {
		tail = tail[1:]
	}
	return tail
}
