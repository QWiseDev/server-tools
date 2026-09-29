package web

import (
	_ "embed"
)

// 控制台页面随二进制一起编译发布（单文件部署）。
//
//go:embed static/index.html
var indexHTML []byte

// IndexHTML 返回内嵌的控制台页面内容。
func IndexHTML() []byte { return indexHTML }
