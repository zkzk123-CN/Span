# Span Makefile
# 用法: make <target>

# Go 相关
GO        = go
GOOS      = $(shell go env GOOS)
GOARCH    = $(shell go env GOARCH)
LDFLAGS   = -s -w -buildid=
GCFLAGS   = -trimpath
BUILDTAGS = netgo
CGO       = CGO_ENABLED=0

# 版本信息（可通过环境变量覆盖）
VERSION   ?= 0.1.0
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILDTIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# 输出目录
BIN_DIR   = bin

# 默认目标
.PHONY: all
all: build

# 构建（当前平台）
.PHONY: build
build:
	$(CGO) $(GO) build $(GCFLAGS) -tags $(BUILDTAGS) \
		-ldflags "$(LDFLAGS) -X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)' -X 'main.BuildTime=$(BUILDTIME)'" \
		-o $(BIN_DIR)/span ./cmd/span/
	@echo "[+] Built: $(BIN_DIR)/span"
	@ls -lh $(BIN_DIR)/span | awk '{print "[+] Size:", $$5}'

# Windows 交叉编译
.PHONY: build-windows
build-windows:
	GOOS=windows GOARCH=amd64 $(CGO) $(GO) build $(GCFLAGS) -tags $(BUILDTAGS) \
		-ldflags "$(LDFLAGS) -X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)' -X 'main.BuildTime=$(BUILDTIME)'" \
		-o $(BIN_DIR)/span_windows_amd64.exe ./cmd/span/
	@echo "[+] Built: $(BIN_DIR)/span_windows_amd64.exe"
	@ls -lh $(BIN_DIR)/span_windows_amd64.exe | awk '{print "[+] Size:", $$5}'

# Linux 交叉编译
.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 $(CGO) $(GO) build $(GCFLAGS) -tags $(BUILDTAGS) \
		-ldflags "$(LDFLAGS) -X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)' -X 'main.BuildTime=$(BUILDTIME)'" \
		-o $(BIN_DIR)/span_linux_amd64 ./cmd/span/
	@echo "[+] Built: $(BIN_DIR)/span_linux_amd64"
	@ls -lh $(BIN_DIR)/span_linux_amd64 | awk '{print "[+] Size:", $$5}'

# 全平台编译
.PHONY: build-all
build-all: build-windows build-linux
	@echo "[+] All builds complete"

# UPX 压缩（需要安装 upx）— Go 二进制不兼容 --ultra-brute，使用 --best --lzma
.PHONY: compress
compress: build
	@command -v upx >/dev/null 2>&1 || { echo "[-] UPX not installed"; exit 1; }
	upx --best --lzma $(BIN_DIR)/span
	@echo "[+] Compressed:"
	@ls -lh $(BIN_DIR)/span | awk '{print "[+] Size:", $$5}'

# 运行测试
.PHONY: test
test:
	$(GO) test -v ./...

# 代码格式化
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# 代码检查
.PHONY: vet
vet:
	$(GO) vet ./...

# 清理
.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	@echo "[+] Cleaned"

# 依赖管理
.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: deps
deps:
	$(GO) mod download

# 帮助
.PHONY: help
help:
	@echo "Span - 内网横向移动分析工具"
	@echo ""
	@echo "Available targets:"
	@echo "  build           编译当前平台二进制"
	@echo "  build-windows   交叉编译 Windows amd64"
	@echo "  build-linux     交叉编译 Linux amd64"
	@echo "  build-all       编译全平台"
	@echo "  compress        UPX 压缩二进制（需安装 upx）"
	@echo "  test            运行测试"
	@echo "  fmt             格式化代码"
	@echo "  vet             代码检查"
	@echo "  clean           清理构建产物"
	@echo "  tidy            整理依赖"
	@echo "  help            显示帮助"
