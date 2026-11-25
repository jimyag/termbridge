# 使用参考

完整配置见 [termbridge.example.yaml](../termbridge.example.yaml)。

## 命名连接与多级组合

`connections` 按名称保存连接配置，每种 `type` 使用自己的字段。`via` 指定使用哪个前置连接、到达哪个固定中转位置。

```yaml
connections:
  bastion:
    type: jumpserver
    url: https://jump.example.com/api/v1
    org: DEFAULT
    access_key_id: "<AK>"
    access_key_secret: "<SK>"
    known_hosts: ./known_hosts

  relay:
    type: ssh
    user: operator
    via:
      connection: bastion
      asset: gateway
      account: operator

  office:
    type: pty
    user: operator
    command: [remote-login]
    via:
      connection: relay
      host: relay-host

allow:
  bastion:
    - asset: gateway
      account: operator
  relay:
    - host: relay-*
  office:
    - host: node-*
```

调用 `office` 并指定 `node-1234`，程序会展开整条链路。

```text
Termbridge → JumpServer 资产 gateway
           → SSH 主机 relay-host
           → PTY 包装器连接 node-1234
```

每个命名连接都能单独作为调用入口。例如调用 `relay` 会自动经过 `bastion`。配置加载时检查未知连接、循环引用、无效中转目的地和类型字段。

`allow` 限制调用方可选择的最终目的地。固定的中转位置由 `via` 配置授权，未配置 allow 的连接可以作为固定前置使用。

| type | 连接配置 | 调用或 via 的目的地 |
| --- | --- | --- |
| `ssh` | 默认 `user`、`port`，可选 `identity_file`、`known_hosts` | `host`，可覆盖 `user`、`port` |
| `jumpserver` | `url`、`org`、`access_key_id`、`access_key_secret`，可选 `known_hosts` | `asset`、`account` |
| `pty` | `command`、默认 `user` | `host`、可选 `user` |
| `kubectl` | `context`、默认 `namespace`、`container` | `pod`，可覆盖 `namespace`、`container` |
| `docker` | `context`、默认 `user` | `container`、可选 `user` |

默认值先合并，再进行授权校验。allow 的 host、asset、pod 和 Docker container 支持一个 `*` 通配符。账号、用户、端口、namespace 和 Pod container 精确匹配。覆盖默认值后，最终参数仍须匹配 allow。

每一步都在上一步到达的位置启动。对应的 SSH、Python、包装器、kubectl 或 Docker CLI，以及认证配置，需要在那个执行位置可用。kubectl 和 Docker 使用各自连接配置中的 context。

### SSH

默认 user 已配置时，host 填主机名，账号通过 user 指定。没有默认 user 时，也可以使用 `user@host`。

SSH 启用主机公钥校验、非交互认证，并关闭 Agent 转发。可以指定 identity_file。首段连接的相对 known_hosts 和 identity_file 路径按配置文件目录解析。后续 SSH 的路径属于远端执行位置，建议使用绝对路径。

### JumpServer

每个 JumpServer 连接保存自己的地址、组织和 AK/SK。含凭据的实际配置文件要求组和其他用户没有访问权限，通常使用 `0600`。

JumpServer 当前须位于链路首段。程序查询当前用户授权的资产和账号，将账号用户名或别名解析成连接令牌需要的别名。账号匹配有歧义时拒绝连接。省略 account 时使用 API Key 所属用户名。省略 org 时使用 `ROOT`。

### PTY 包装器

command 是可执行文件与固定参数组成的数组，例如 `[remote-login, --profile, office]`。程序随后追加目的地与远程命令两个参数。包装器须支持这种调用约定，并连接远程输入输出。

执行包装器的位置需要 Python 3。最终目的地的 stdin 是 TTY 时，还需要 stty 来关闭行缓冲和回显。`remote-login` 是示例名称，须替换为实际工具。

## CLI

```bash
./termbridge exec --connection office --host node-1234 --command 'ps -ef | head -20'
./termbridge exec --connection cluster --pod app-1 --command 'df -h'
./termbridge exec --connection containers --container worker-1 --command 'uname -a'
```

支持管道、重定向和多行脚本。CLI 的 stdout 返回命令输出，stderr 输出运行日志，进程退出码对应远端命令退出码。连接、配置或协议错误返回非零状态。每次 CLI 调用结束时关闭连接。

`./termbridge exec --help` 显示各连接类型可用的目的地参数。

## MCP

在支持 mcpServers 配置格式的客户端中，可以按以下方式添加 stdio 服务。路径使用实际的绝对路径。

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

| 工具 | 参数 | 返回 |
| --- | --- | --- |
| `terminal_open` | `{"connection":"office","host":"node-1234"}` | session_id |
| `terminal_run` | `{"session_id":"…","command":"uname -a; uptime"}` | output、exit_code、truncated |
| `terminal_close` | `{"session_id":"…"}` | closed |

同一个 session_id 可以执行多条命令，复用整条连接链。命令串行执行，每条命令在独立的 `sh -c` 进程中运行，cd 和 export 的状态不会跨调用保留。stdin 连接到 /dev/null，执行方式为非交互。stdout 与 stderr 合并返回。

`terminal_close` 可重复调用。服务退出时会关闭剩余会话。

| 项目 | 上限 |
| --- | --- |
| 建立整条连接链 | 30 秒 |
| 单条命令执行 | 20 秒 |
| 命令长度 | 32 KiB |
| 返回输出 | 32 KiB |
| 会话空闲 | 约 10 分钟 |

空命令和包含 NUL 的命令会被拒绝。超出输出上限时截断文本，truncated 为 true，连接仍可继续使用。超时、取消或缺少完成标记时关闭通道，命令结果标为未知，需要重新打开会话。远端进程的终止由对应 SSH 或容器执行环境负责。

## 操作日志

正常运行时，每行日志是一个 JSON 对象，默认写入 stderr。MCP 的 stdout 用于协议通信，CLI 的 stdout 用于命令输出。

通过配置开启文件记录。相对路径按配置文件所在目录解析。

```yaml
logging:
  file: ./logs/termbridge.jsonl
```

启用文件记录后，同一条日志会同时写入文件和 stderr。文件以追加方式打开，新文件权限为 `0600`，新建目录权限为 `0700`。现有日志文件须为普通文件，且组和其他用户没有访问权限。符号链接、FIFO 和当前配置文件会被拒绝。

省略 logging.file 时，只记录到 stderr。日志文件写入失败时，会在 stderr 记录 `logging.write` 错误，并继续将操作记录写到 stderr。配置加载失败和日志初始化失败也会记录到 stderr。文件持续追加，轮转和保留周期由运行环境管理。

### 记录内容

| event | 记录内容 |
| --- | --- |
| `service.run` | CLI 或 MCP 启动、退出状态与运行时长 |
| `terminal.open` | 请求目的地、展开后的链路、建立结果与会话 ID |
| `terminal.run` | 命令、输出、退出码、截断标志、耗时及失败原因 |
| `terminal.close` | 显式关闭、空闲回收、连接失效回收或服务退出时的关闭 |

操作开始与结束使用相同的 operation_id，每个会话有独立的 session_id。记录包含 time、level、local_uid、event 和 phase。结束记录包含 status 和 duration_ms。

拿到退出码时 result_known 为 true。非零退出码会记录为 failed，同时保留 exit_code 和输出。超时、取消、未知会话或协议中断时 result_known 为 false，省略 exit_code，并记录错误。协议中断或取消时，已收到的部分输出也会保留在日志中。

close 记录的 reason 可以是 requested、idle_timeout、connection_closed 或 shutdown。重复关闭时 found 为 false。

查询失败操作可使用 jq。

```bash
jq -c 'select(.phase == "finished" and .status == "failed")' logs/termbridge.jsonl
jq -c 'select(.event == "terminal.run" and .phase == "finished") | {session_id, command, output, exit_code, error}' logs/termbridge.jsonl
```

### 日志中的敏感信息

配置中的 AK/SK 会按完整字面值匹配，替换为 `[REDACTED]`。脱敏发生在日志字段裁剪之前。命令日志最多保留 32 KiB 文本，命令过长时还会记录原始字节数及 command_truncated。输出是经过控制字符过滤的文本，保留范围与返回结果一致。

日志包含完整命令和捕获到的输出，可能涉及配置之外的密码、令牌或业务数据。访问权限和保留策略需要按这些内容管理。脱敏范围和执行权限见 [SECURITY.md](../SECURITY.md)。

## 常见问题

| 现象 | 检查位置 |
| --- | --- |
| destination is outside the configured allow rules | 最终参数合并默认值后是否匹配 allow |
| terminal ended before readiness | 当前执行位置是否具备对应 CLI、凭据和远端 sh，TTY 目的地是否提供 stty |
| result unknown 或 command interrupted | 日志中的部分输出和错误，重新建立会话后查询实际状态 |
| audit log requires a regular file with permissions 0600 | 日志文件类型与访问权限 |
| JumpServer 账号匹配失败 | 资产授权、实际账号用户名或别名，以及所配置的组织 |

开发检查、隔离环境测试和发布流程见 [CONTRIBUTING.md](../CONTRIBUTING.md)。
