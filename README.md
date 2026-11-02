# Veydeck 协议仿真套件

本仓库维护协议仿真套件源码。套件交付包、`suite.yaml`、`compose.yaml` 和套件版本发布由 `veydeck-suites` 仓库维护。

Veydeck 是一个可扩展的分布式 Linux 主机运维平台，用于统一管理一台或多台 Linux 主机，并支持通过套件按需扩展平台能力。

## 目录

| 路径 | 说明 |
| --- | --- |
| `crates/protocol-simulation` | 套件 API 服务，负责规则库、实例状态、PCAP 记录和 Agent suite workload API 调用。 |
| `crates/protocol-simulation-engine` | 协议仿真 workload 进程，由 Agent 按规则拉起独立容器。 |
| `crates/protocol-simulation-common` | API 与 engine 共享模型。 |
| `frontend` | 套件控制台前端。 |
| `assets` | 套件图标等源资产。 |
| `scripts` | 镜像构建脚本。 |

## 本地开发

```bash
pnpm -C frontend install
pnpm -C frontend dev
cargo run -p protocol-simulation
cargo run -p protocol-simulation-engine
```

API 服务默认监听 `8080`，数据目录为 `/data`，可通过 `VEYDECK_SUITE_DATA_DIR` 覆盖。engine 只读取 Agent 注入的 `VEYDECK_WORKLOAD_CONFIG_JSON` v1 启动描述，并按其中的具名端点监听固定容器端口。

## 镜像构建

```bash
./scripts/build-image.sh
./scripts/build-engine-image.sh
```

不传参数时，脚本分别从对应 crate 的 `Cargo.toml` 读取镜像标签：

- `scripts/build-image.sh` 读取 `crates/protocol-simulation/Cargo.toml`
- `scripts/build-engine-image.sh` 读取 `crates/protocol-simulation-engine/Cargo.toml`

也可以显式传入镜像标签：

```bash
./scripts/build-image.sh 0.1.0-alpha.1
./scripts/build-engine-image.sh 0.1.0-alpha.1
```

默认镜像名：

- `veydeck/protocol-simulation`
- `veydeck/protocol-simulation-engine`

## 运行边界

套件 API 容器只维护套件状态和调用 Agent。协议仿真实例由 Agent 通过 suite workload API 拉起 engine 容器，容器生命周期和 PCAP 取证归属当前节点 Agent。

规则包导入、实例部署、下线和取证接口由套件 API 提供；主控只负责安装套件、代理入口、注入运行配置和展示统一通知。

当前 v1 能力目录覆盖 HTTP、Redis、SMTP、POP3、IMAP、SSH、FTP、RDP、Telnet、MySQL、PostgreSQL、SMB、LDAP、DNS、MongoDB、Memcached、SNMP、MQTT 和 VNC。DNS 规则同时声明 53/TCP 与 53/UDP 容器端点；SNMP 声明 161/UDP 端点。实例、Agent workload、整工作负载 PCAP、engine 启动描述和审计事件均使用具名端点。

MongoDB、Memcached、SNMP、MQTT 和 VNC 当前提供面向扫描识别的握手、版本或探测响应，不提供完整数据库、缓存、消息代理、SNMPv3 或远程桌面会话。

Veydeck 会把 `/run/veydeck-agent/runtime.json` 及实例令牌以只读方式注入套件。套件 API 根据描述自动连接本地 UDS 或节点 mTLS HTTPS，不读取 Agent mode，也不接受客户端自行指定套件实例身份。

套件后端通过 Suite Runtime SDK 使用 `operation-logs.write` 能力记录规则、仿真实例和抓包生命周期；查询、下载、进度和内部引擎事件不进入平台操作日志。

## 协议识别验收

19 种协议的 Banner、服务身份字段、能力边界和 Nmap/客户端复测方式见 [协议发现验收矩阵](docs/protocol-discovery.md)。
