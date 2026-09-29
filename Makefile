# server-mcp 构建
# 注意：全局 go env 可能设了 GOOS=linux（服务器交叉编译用），
# 所有目标都显式指定平台，避免编出跑不起来的二进制。

BINARY  := server-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build release-linux release-linux-arm64 test vet clean

build: ## 本机可执行（自动匹配本机平台，忽略全局 GOOS 设置）
	GOOS=$$(go env GOHOSTOS) GOARCH=$$(go env GOHOSTARCH) \
		go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/server

release-linux: ## Linux x86_64 服务器版 → dist/
	GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-amd64 ./cmd/server

release-linux-arm64: ## Linux arm64 服务器版 → dist/
	GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-arm64 ./cmd/server

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf dist $(BINARY)
