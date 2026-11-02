# 协议 Banner 与服务识别验收

本套件的 Banner 指协议允许公开的欢迎语、握手版本、服务身份或能力信息。不是所有协议都会在连接建立后主动发送文本，也不是所有协议都公开产品版本。

## 配置契约

- SMTP、POP3、IMAP、FTP 的 `banner` 只填欢迎语正文，状态前缀及 CRLF 由引擎生成。SSH 的 `banner` 填完整的 `SSH-2.0-...` 版本行，不包含 CRLF。Telnet 的 `banner` 填单行欢迎语，协议协商和换行由引擎生成。
- Redis 无 `banner` 字段，不主动发送欢迎语。使用 `server_version` 配置版本，`INFO` 返回服务身份。`server_info` 覆盖默认信息，显式 `server_version` 对版本有最终优先级，每个字段只返回一次。开启认证时，PING、INFO 和自定义命令均受认证限制，AUTH 除外。
- LDAP 使用 `base_dn`、`vendor_name`、`vendor_version`，提供匿名 LDAPv3 Bind 和 RootDSE 基础范围搜索。只支持 `(objectClass=*)`；支持属性选择及 typesOnly。具名 Bind 返回认证失败，非 RootDSE 查询返回 noSuchObject，不提供目录内容。
- DNS 的 `server_version` 对应 `version.bind CH TXT`；`server_name` 对应 `id.server CH TXT`。TCP/UDP 使用同一响应构造器；保留 IN A 查询。未配置身份时默认返回 `9.18.30` 和 `dns.veydeck.local`。
- SMB 的 `server_name`、`domain` 出现在 SMB2 Session Setup 的 NTLM challenge 中。支持 SMB 2.0.2/2.1 协商，不提供 SMB1 会话、文件访问、签名会话或真实身份认证。
- RDP 行为配置为 `{}`。只响应 X.224 协商，支持 Standard RDP Security；不支持的 TLS/NLA 请求返回协商失败，不声明未实现的能力。
- HTTP/1 响应采用常规 Title-Case 标头以支持区分大小写的探针。HTTP 在普通响应和配置的路径响应中均返回 `server_header`，缺省为 `nginx/1.24.0`；该字段覆盖自定义响应头中的 Server。
- Memcached 的 VERSION 与 STATS 使用同一个 `server_version`，自定义 stats 不重复覆盖内置身份与统计字段。

这是 alpha 阶段的直接契约调整。Redis `banner`、RDP `flags/credentials`、SMB `shares`、LDAP `credentials/entries` 已删除，提交这些字段会报错；不提供迁移或兼容转换。

## 验收矩阵

默认和自定义配置各执行一遍；每遍都测试标准端口与加 20000 的映射端口。映射层只转发数据，不修改引擎启动描述中的固定容器端口。

| 协议 | 协议客户端/报文检查 | Nmap 验收 | 可见范围 |
| --- | --- | --- | --- |
| HTTP | Python http.client GET `/`、`/probe`，检查 Server 一致 | 服务探测 | 匿名 |
| Redis | 无主动数据；PING、INFO、AUTH，分包与连续命令 | 无认证时服务探测，需认证时官方 redis-info NSE 携带合成凭据 | 配置认证后需先 AUTH |
| SMTP | Python smtplib，欢迎语、EHLO、AUTH | 服务探测 | 欢迎语匿名，认证另验 |
| POP3 | Python poplib，欢迎语、CAPA、登录 | 服务探测 | 欢迎语匿名，认证另验 |
| IMAP | Python imaplib，欢迎语、CAPABILITY、登录 | 服务探测 | 欢迎语匿名，认证另验 |
| SSH | 版本行及版本交换 | 服务探测 | 匿名；不实现加密登录 |
| FTP | Python ftplib，欢迎语、FEAT、登录 | 服务探测 | 欢迎语匿名，认证另验 |
| RDP | 分包 X.224 请求，标准协商及 TLS/NLA 拒绝 | 服务探测 | 匿名；不要求 Windows 版本 |
| Telnet | IAC、欢迎语、协商回复、登录提示和认证 | 服务探测 | 欢迎语匿名，认证另验 |
| MySQL | 解码握手，native_password 登录和 VERSION 查询 | 服务探测 | 版本匿名可见 |
| PostgreSQL | SSLRequest、启动认证、ParameterStatus、版本查询 | 服务探测 | 精确版本需认证 |
| SMB | SMB2 协商、Session Setup、解析 NTLM 服务器名和域名 | 官方 smb-protocols NSE | 匿名；不要求 OS 版本 |
| LDAP | BER 分包、多字节消息 ID、RootDSE 属性 | 官方 ldap-rootdse NSE | 匿名 |
| DNS | TCP/UDP A、version.bind、id.server | TCP/UDP 服务探测 | 匿名 |
| MongoDB | OP_MSG buildInfo，检查 responseTo 与版本 | 服务探测 | 匿名 |
| Memcached | 分包和连续 VERSION/STATS 请求 | 服务探测 | 匿名 |
| SNMP | v2c GET sysDescr.0 | UDP 服务探测 | 需匹配 community |
| MQTT | 3.1.1/5 CONNECT、CONNACK、PINGRESP | 服务探测 | 不要求 broker 产品版本 |
| VNC | RFB 版本、安全类型、客户端降到 3.3、认证失败挑战 | 服务探测 | 不要求产品或桌面版本 |

Nmap 首先执行 `--version-light`，对未识别端口独立追加 `--version-all`；两阶段 XML 均保留。Nmap 的 SMB 通用探针只发送 SMB1 方言，因此 SMB2-only 服务通过官方 `smb-protocols` 验收。LDAP 使用官方 `ldap-rootdse` 验证真实属性。脚本不会把按端口查表得到的服务名算作识别成功。

Nmap 的产品标签来自指纹推断，协议版本不等于产品版本；应同时核对客户端解码得到的配置值。SSH、RDP 和 VNC 不提供完整会话。

## 复测命令

需要 Docker 和可在 Ubuntu 24.04 运行的 Linux engine 二进制。先构建 engine，再构建固定 Nmap 包版本的验收镜像：

```bash
cargo build -p protocol-simulation-engine
docker build -f scripts/Dockerfile.probe -t veydeck-protocol-discovery:7.94 .
docker run --rm --name veydeck-banner-acceptance \
  -v "$PWD:/workspace" -w /workspace \
  veydeck-protocol-discovery:7.94
```

测试在容器独立网络中绑定标准端口，不发布宿主机端口。测试配置和口令均为合成数据。可使用 `--skip-nmap` 只运行客户端检查，或 `--profile custom` 只运行自定义配置：

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace \
  veydeck-protocol-discovery:7.94 \
  python3 scripts/probe-protocols.py --skip-nmap --profile custom
```

输出位于 `target/discovery-acceptance/`：

- `environment.json`：engine SHA-256、Nmap 版本、官方 service-probes SHA-256。
- `default/`、`custom/`：启动配置、引擎日志、客户端结果、Nmap 原始 XML/日志/命令及最终结果。
- `events.jsonl`：合成测试的审计事件及请求 payloadHex，便于排查失败报文。

脚本对客户端断言失败、Nmap 命令失败、扫描缺失或识别失败返回非零状态。不提交生成结果；发布前以该次 engine 哈希对应的完整报告为准。

Rust 单元测试另覆盖非法配置、移除字段拒绝、BER/RESP 长度、分包/连续消息、截断/异常断连、空闲超时、SMB 偏移边界、LDAP 属性筛选、版本一致性和数据库认证失败。
