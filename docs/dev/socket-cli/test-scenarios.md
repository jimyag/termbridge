# 本地服务与 CLI 测试场景

## 范围与实现计划

CLI → Unix socket HTTP/JSON → serve → 现有 terminal.open/run/close → 目的地。

`internal/termbridge/cli.go` 改为 serve/open/run/close/exec 入口；新增 `server.go` 实现本地传输，沿用 `session.go` 的权限、超时、串行化和回收逻辑。仅 serve 读取配置与记录操作日志。移除 MCP SDK，迁移现有 SSH、JumpServer、容器和审计测试，更新 README、使用说明与安全说明。不增加网络监听、自动启动后台或额外依赖。

默认 socket 为 `~/.termbridge/run.sock`，可通过所有子命令的 `--socket` 覆盖。目录要求当前用户所有且权限 0700，socket 要求当前用户所有且权限 0600；拒绝符号链接与已有路径，不自动删除残留 socket。客户端仅访问本地 socket，不读取服务配置。serve 前台运行，收到退出信号后取消请求、关闭会话并移除自己的 socket。

先实现服务及客户端，随后迁移现有测试，最后执行真实二进制调用、竞态检查、独立审查和构建检查。涉及 CLI、传输、测试、依赖与文档超过 8 个文件。回退可以恢复旧提交并重新构建，无持久业务数据迁移；内存会话在重启后失效，已在远端执行的命令不能靠回退撤销。

## 场景

| ID | Given / When / Then | 类型 | 优先级 | 状态 | 证据 |
| --- | --- | --- | --- | --- | --- |
| TS-1 | 已启动服务，独立 CLI 进程 open 后多次 run，复用同一会话；close 后拒绝 run，重复 close 成功 | integration | P0 | covered | TestCLIProcessesReuseSession：两次独立 run 返回同一个远端父进程 PID，关闭后拒绝命令 |
| TS-2 | 服务未启动或命令、参数、JSON 无效，明确失败，不执行远端命令 | integration | P0 | covered | TestCLIRequiresServiceAndValidArguments、TestServiceRejectsInvalidRequests |
| TS-3 | socket 目录或节点权限过宽、符号链接、非 socket、已有服务路径，拒绝且不删除原路径 | integration | P0 | covered | TestSocketRejectsUnsafeAndExistingPaths、TestSocketPermissionsAndRestart、TestShutdownPreservesReplacementAtSocketPath |
| TS-4 | 同会话并发 run 串行执行；不同会话独立；客户端取消后中断命令并关闭会话 | integration | P0 | covered | TestConcurrentSocketCommandsStayInTheirSession、TestServiceShutdownAndConcurrentSessions、TestClientCancellationClosesSession |
| TS-5 | 服务退出关闭会话、取消在途请求、移除自身 socket；重启后旧 ID 无效 | integration | P0 | covered | TestServiceShutdownAndConcurrentSessions、TestSocketPermissionsAndRestart；子进程清理断言 socket 不存在 |
| TS-6 | SSH、PTY、多级链路与 JumpServer 测试替身保留任意命令、权限拒绝、退出码、UTF-8、截断和审计脱敏行为；空闲 10 分钟回收 | integration/unit | P0 | covered | TestSSH、TestJumpServer、TestArbitraryShellProtocol、TestServiceAudit、TestIdleSessionExpires；go test -race -count=1 -timeout=2m ./... |
| TS-7 | 真实编译产物启动 serve，经独立 open/run/close/exec 返回输出、错误退出码与服务端日志 | manual | P0 | covered | macOS arm64 运行竞态二进制，Docker BusyBox 1.37：重复 run 远端父 PID 同为 6；远端 exit 7 保留；40,000 字节输出截断为 32,768 后可继续 run；exec 输出 one-shot；SIGTERM 后 socket 消失且审计包含退出码 |

现有协议及权限测试验证连接和执行行为，不能证明真实外部堡垒机与集群部署。新的 Unix socket 测试验证本机进程边界及文件权限，不能替代不同操作系统用户的人工权限验收。验收入口：构建 `./cmd/termbridge`，启动 `serve --config <fixture> --socket <private-dir>/s`，分别调用 `open`、两次 `run`、`close`，确认最后的 `run` 失败；退出服务后确认 socket 已移除。

## 需求到证据

| 需求 | 场景 | 实现与验证入口 |
| --- | --- | --- |
| 显式启动本地服务，后续命令连接服务 | TS-1、TS-2、TS-7 | cli.go 的 Run/runService；TestCLIProcessesReuseSession；上述手工验收流程 |
| 保留持久会话、权限与日志 | TS-4、TS-5、TS-6 | session.go；TestServiceAudit；TestIdleSessionExpires；TestConcurrentSocketCommandsStayInTheirSession |
| 本地服务仅允许当前用户访问并安全清理 | TS-3、TS-5 | server.go；TestSocketRejectsUnsafeAndExistingPaths；TestShutdownPreservesReplacementAtSocketPath |

运行 `go test ./internal/termbridge -run '<测试名>'` 可单独重放对应场景。Kubernetes 集群和其他 OS 用户的权限验收本轮未运行；本地容器验收不代表外部部署已经验收。临时 Docker 容器、服务进程和 socket 已清理。

## 真实 JumpServer 验收（2026-11-26）

使用本地 `jumpserver/jms_all:v4.10.19`，启动实际 Core、KoKo、PostgreSQL 和 Redis，配两台 Alpine 3.22 OpenSSH 目标容器。初始化使用普通用户、资产账号和显式资产授权，保留一个未授权资产作为拒绝场景。API 经本机 HTTPS 终止器原样转发到真实 Core，服务仅信任本次临时证书，未关闭 TLS 或 KoKo 主机公钥校验。

实际编译产物通过 Unix socket 执行四条链路：

- JumpServer → 目标机。
- JumpServer → 中转机 → SSH → 目标机。
- JumpServer → 中转机 → 要求 TTY 的 PTY 包装器 → 目标机。
- JumpServer → 中转机 → SSH → PTY 包装器 → 目标机。

每条链路执行 8 条命令，覆盖实际 hostname、两次远端父进程 PID 比较、带引号的中文多行脚本与管道、stdin EOF、退出码 7、40,000 字节输出截断为 32,768，以及截断后继续执行。不同 CLI 进程两次查询得到同一个远端父进程 PID；每条链路在真实 JumpServer 数据库中只增加一个 ConnectionToken 和一条 Session，证明多次 run 没有重新登录。

每条会话重复 close 成功，关闭后 run 被拒绝。未授权资产由真实 JumpServer 权限查询拒绝，本地 allow 拒绝另外一个非法目的地，两种失败均未增加连接令牌或会话。额外验证一次性 exec、服务端审计对实际测试 AK/SK 的脱敏，以及服务退出时关闭未显式 close 的会话。共获得 34 条已知命令结果；最终真实 JumpServer 数据库有 6 条会话，活动会话为 0，Unix socket 已移除。隔离容器、网络、临时证书、配置与凭据在验收后清理。
