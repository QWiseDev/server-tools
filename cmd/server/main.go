// server-mcp 入口：装配配置、鉴权、能力实现与 HTTP 服务。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"servermcp/internal/arthas"
	"servermcp/internal/auth"
	"servermcp/internal/config"
	"servermcp/internal/dbquery"
	"servermcp/internal/fsbrowse"
	"servermcp/internal/logsw"
	"servermcp/internal/mcpserver"
	"servermcp/internal/shell"
	"servermcp/internal/web"
)

var version = "1.0.0"

func main() {
	cfgPath := flag.String("config", "", "config.json 路径（缺省用内置默认值）")
	showVersion := flag.Bool("version", false, "打印版本号")
	flag.Parse()
	if *showVersion {
		fmt.Println("server-mcp", version)
		return
	}

	cfg, where, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("[server-mcp] %v", err)
	}
	fmt.Printf("[server-mcp] v%s 配置: %s；控制台密码=%s；shell=%v\n",
		version, where, onOff(cfg.AdminPassword != ""), onOff(cfg.ShellEnabled))

	// 密钥与能力装配
	keys := auth.NewKeyStore(cfg.KeysPath, mcpserver.AllTools())
	if err := keys.EnsureLoad(); err != nil {
		log.Fatalf("[server-mcp] %v", err)
	}
	runner, err := shell.NewRunner(cfg)
	if err != nil {
		log.Fatalf("[server-mcp] %v", err)
	}

	srv := web.Server{
		Cfg:    cfg,
		Keys:   keys,
		Sess:   auth.NewSessions(time.Duration(cfg.SessionTTLH) * time.Hour),
		Shell:  runner,
		Logs:   logsw.NewManager(cfg),
		DB:     dbquery.New(cfg.DBPath, cfg.MaxOutput),
		Arthas: arthas.New(cfg),
		FS:     fsbrowse.New(cfg.FsRoots),
	}
	mc := mcpserver.NewServer(mcpserver.Deps{
		Shell:  runner,
		Logs:   srv.Logs,
		DB:     srv.DB,
		Arthas: srv.Arthas,
		Keys:   keys,
	}, version)
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mc }, nil)

	mux := http.NewServeMux()
	srv.Register(mux, mcpHandler, web.IndexHTML())
	handler := web.AuthGuard(cfg, keys, srv.Sess)(mux)

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 优雅退出
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		fmt.Println("[server-mcp] 收到退出信号，正在关闭…")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	fmt.Printf("[server-mcp] 监听 http://%s:%d（控制台 / ，MCP 端点 /mcp）\n", cfg.Host, cfg.Port)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[server-mcp] %v", err)
	}
}

func onOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}
