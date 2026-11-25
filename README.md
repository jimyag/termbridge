# Termbridge

通过 SSH、JumpServer、PTY 包装器、kubectl 或 Docker 进入目标环境，执行任意 shell 命令。提供 CLI 和 stdio MCP，支持命名连接、多级 `via` 和会话复用。

## 快速使用

需要 Go 1.26+，运行环境为 Linux 或 macOS。

```bash
go build -o termbridge .
cp termbridge.example.yaml termbridge.yaml
chmod 600 termbridge.yaml
```

填写配置中的地址、账号和 AK/SK，再指定连接名、最终目的地与命令。

```bash
./termbridge exec --connection office --host node-1234 --command 'uname -a; uptime'
./termbridge exec --connection cluster --pod app-1 --command 'df -h'
./termbridge exec --connection containers --container worker-1 --command 'ps -ef'
```

默认读取 `termbridge.yaml`，可用 `--config` 指定其他 YAML 或 JSON 文件。完整配置见 [termbridge.example.yaml](termbridge.example.yaml)。

## MCP

服务启动参数为 `termbridge mcp --config /path/to/termbridge.yaml`。支持 mcpServers 格式的客户端可参考以下配置。

```json
{
  "mcpServers": {
    "termbridge": {
      "command": "/path/to/termbridge",
      "args": ["mcp", "--config", "/path/to/termbridge.yaml"]
    }
  }
}
```

| 工具 | 参数示例 |
| --- | --- |
| `terminal_open` | `{"connection":"office","host":"node-1234"}` |
| `terminal_run` | `{"session_id":"…","command":"uname -a; uptime"}` |
| `terminal_close` | `{"session_id":"…"}` |

同一会话复用整条连接链，空闲 10 分钟后回收。每条命令在独立的非交互 sh 中执行，最长 20 秒，输出最多 32 KiB，cd 和 export 不跨调用保留。

## 日志

操作、命令、输出、退出码和错误以 JSON 写入 stderr。配置以下路径可同时落盘，文件权限为 `0600`，配置中的完整 AK/SK 字面值自动脱敏。

```yaml
logging:
  file: ./logs/termbridge.jsonl
```

## 开发与发布

CI 检查 PR 和 main 分支，执行 lint、Linux/macOS 竞态测试及交叉构建。推送 `v*` 标签后，通过同一套检查再自动发布 Linux/macOS 的 amd64、arm64 二进制和 checksums.txt。

- [使用参考](docs/usage.md) 包含配置字段、链式连接、运行限制、日志与排障。
- [开发约定](CONTRIBUTING.md) 包含本地检查、集成测试与发布验证。
- [安全说明](SECURITY.md) 包含执行权限、凭据和日志的处理边界。
