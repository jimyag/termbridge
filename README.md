# Termbridge

通过 SSH、JumpServer、PTY 包装器、kubectl 或 Docker 进入目标环境，执行任意 shell 命令。命令行客户端连接本地服务，支持命名连接、多级 `via` 和会话复用。

## 快速使用

需要 Go 1.26+，运行环境为 Linux 或 macOS。

```bash
go build -o termbridge ./cmd/termbridge
cp termbridge.example.yaml termbridge.yaml
chmod 600 termbridge.yaml
```

填写配置中的地址、账号和 AK/SK，启动服务。默认读取 `termbridge.yaml`，可用 `--config` 指定其他 YAML 或 JSON 文件。

```bash
./termbridge serve --config termbridge.yaml
```

在另一个终端打开会话并执行命令。完整配置见 [termbridge.example.yaml](termbridge.example.yaml)。

```bash
session=$(./termbridge open --connection office --host node-1234)
./termbridge run --session "$session" --command 'uname -a; uptime'
./termbridge run --session "$session" --command 'df -h'
./termbridge close --session "$session"
```

一次性命令可使用 `./termbridge exec --connection office --host node-1234 --command 'uptime'`，同样要求服务已启动。

默认通过 `~/.termbridge/run.sock` 通信。所有子命令支持 `--socket` 指定其他路径，所在目录须由当前用户拥有且权限为 `0700`。`serve` 前台运行，Ctrl-C 关闭服务与所有会话；可由系统服务管理器托管。客户端不会自动启动服务，配置变更需要重启服务。

同一会话复用整条连接链，空闲 10 分钟后回收。每条命令在独立的非交互 sh 中执行，最长 20 秒，输出最多 32 KiB，cd 和 export 不跨调用保留。

## 日志

服务端将操作、命令、输出、退出码和错误以 JSON 写入 stderr。客户端默认输出会话 ID 或命令文本，`--json` 返回结构化结果。配置以下路径可同时记录服务端日志，文件权限为 `0600`，配置中的完整 AK/SK 字面值自动脱敏。

```yaml
logging:
  file: ./logs/termbridge.jsonl
```

## 开发与发布

CI 检查 PR 和 main 分支，执行 lint、Linux/macOS 竞态测试及交叉构建。推送 `v*` 标签后，通过同一套检查再自动发布 Linux/macOS 的 amd64、arm64 二进制和 checksums.txt。

- [使用参考](docs/usage.md) 包含配置字段、链式连接、运行限制、日志与排障。
- [开发约定](CONTRIBUTING.md) 包含本地检查、集成测试与发布验证。
- [安全说明](SECURITY.md) 包含执行权限、凭据和日志的处理边界。
