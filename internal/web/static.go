package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// 控制台页面与静态资源（xterm.js 等）随二进制一起编译发布（单文件部署）。
//
//go:embed all:static
var staticEmbed embed.FS

// IndexHTML 返回内嵌的控制台页面内容。
func IndexHTML() []byte {
	b, _ := fs.ReadFile(staticEmbed, "static/index.html")
	return b
}

// StaticFS 返回 /static/ 路径下的静态资源文件系统。
func StaticFS() http.FileSystem {
	sub, _ := fs.Sub(staticEmbed, "static")
	return http.FS(sub)
}
