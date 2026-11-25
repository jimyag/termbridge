# 开发约定

使用 Go 1.26+。项目根目录为 Go main 包，CLI 和 MCP 共用连接与会话实现。

## 本地检查

CI 使用 golangci-lint 2.15.0、GoReleaser 2.18.3。GoReleaser 的检查需要工作副本具备 Git 远端配置。

```bash
golangci-lint run ./...
go test -race -count=1 -timeout=2m ./...
go build -o termbridge .
goreleaser check
actionlint .github/workflows/check.yaml .github/workflows/release.yaml
```

需要验证可执行文件入口时，将 TERMBRIDGE_TEST_BIN 设置为编译产物的绝对路径，再运行测试。

Docker 集成测试需要设置 TERMBRIDGE_TEST_DOCKER_CONTEXT 和 TERMBRIDGE_TEST_DOCKER_CONTAINER。容器须提供 sh、uptime、df、cat、printf 和标准文本命令。CI 在 Linux runner 中创建临时 BusyBox 容器并启用该测试，macOS runner 执行其余本地测试。

Kubernetes 测试通过 TERMBRIDGE_TEST_KUBECONFIG 指向隔离的 kind-termbridge-verify context，Pod 名为 termbridge-check，container 名同名。默认 CI 不创建 Kubernetes 集群。

## 自动发布

[检查流程](.github/workflows/check.yaml) 在 PR 和 main 分支运行。[发布流程](.github/workflows/release.yaml) 由 v 开头的版本标签触发，复用检查流程，通过后使用 GoReleaser 创建 GitHub Release。

发布产物由 [.goreleaser.yml](.goreleaser.yml) 定义。

```text
termbridge_linux_amd64
termbridge_linux_arm64
termbridge_darwin_amd64
termbridge_darwin_arm64
checksums.txt
```

在具备提交历史和 GitHub 远端的工作副本中，可进行本地发布预演。

```bash
goreleaser release --snapshot --clean
```

预演产物位于 dist/，不会发布到远端。正式发布通过推送版本标签触发，release job 仅申请 contents:write 权限，使用 GitHub 提供的 GITHUB_TOKEN。

## 变更要求

- 连接类型变更同步配置、授权、链路展开、CLI 和 MCP schema。
- 命令协议验证多行、引号、UTF-8、长行、截断、退出码、取消及连续调用。
- 日志变更验证开始与结束的关联、未知结果、部分输出、文件权限、脱敏和并发记录。
- 配置或接口变化同步更新 README、使用参考和配置示例。
- 临时文件放在项目根目录 tmp/，测试资源在结束后清理。

提交信息采用 Conventional Commits，使用 `git commit -s`。本地验证、远程 CI 和实际环境验证分别记录。敏感信息约定见 [SECURITY.md](SECURITY.md)。
