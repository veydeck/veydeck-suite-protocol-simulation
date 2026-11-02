# Changelog

## [Unreleased]

## [0.1.0-alpha.2] - 2026-11-02

### Changed

- 明确协议身份配置契约，移除 Redis banner、RDP 无效参数、SMB shares 与 LDAP 目录/凭据配置，不保留 alpha 历史配置兼容。
- 修复邮件欢迎语重复状态前缀、Redis 主动响应及版本重复、Memcached 版本重复、Telnet 欢迎语边界和 VNC 安全握手。
- 补齐 SMB2/NTLM 身份握手、LDAP RootDSE 和 DNS CHAOS TXT 身份查询；完善 RDP 协商与 PostgreSQL 启动错误响应。
- 新增 19 种协议的客户端/Nmap 验收脚本、固定 Nmap 版本的容器和协议验收矩阵。

## [0.1.0-alpha.1] - 2026-10-14

### Added

- 创建 Veydeck 协议仿真套件全新仓库。
- 支持导入签名 `.vprp` 规则包，并部署 HTTP、Redis、邮件、远程访问、数据库、企业、网络及消息协议仿真实例。
- 支持 TCP/UDP 具名多端点、Agent workload 生命周期、整实例 PCAP 和结构化审计事件。
- 提供基于 Veydeck UI、VDL Token 与 Suite Runtime SDK 的 Vue 3 管理界面。
- 提供规则管理、自定义规则、实例批量操作、诱捕审计和安全 HTML 预览能力。
- 提供 `veydeck/protocol-simulation:0.1.0-alpha.1` 与 `veydeck/protocol-simulation-engine:0.1.0-alpha.1` 镜像构建及手动发布流程。
- 支持跟随 Veydeck 主控实时同步主题与液态玻璃开关，实例部署和规则整编界面支持公共 Liquid Glass 材质。
