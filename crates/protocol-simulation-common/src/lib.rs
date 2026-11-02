//! 协议仿真套件共享类型。
//!
//! API 服务和仿真引擎分别发布镜像，本 crate 用于沉淀两者共享的规则、事件和协议模型。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// 协议仿真引擎向套件 API 上报事件时使用的默认容器网络地址。
pub const DEFAULT_EVENT_CALLBACK_URL: &str =
    "http://veydeck-protocol-simulation:8080/internal/events";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationRuntimeEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub instance_id: String,
    pub endpoint_id: String,
    pub event_type: String,
    pub summary: String,
    pub client_ip: String,
    pub client_port: u16,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    pub payload_hex: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolId {
    Http,
    Redis,
    Smtp,
    Pop3,
    Imap,
    Ssh,
    Ftp,
    Rdp,
    Telnet,
    Mysql,
    Postgresql,
    Smb,
    Ldap,
    Dns,
    Mongodb,
    Memcached,
    Snmp,
    Mqtt,
    Vnc,
}

impl ProtocolId {
    pub const ALL: [Self; 19] = [
        Self::Http,
        Self::Redis,
        Self::Smtp,
        Self::Pop3,
        Self::Imap,
        Self::Ssh,
        Self::Ftp,
        Self::Rdp,
        Self::Telnet,
        Self::Mysql,
        Self::Postgresql,
        Self::Smb,
        Self::Ldap,
        Self::Dns,
        Self::Mongodb,
        Self::Memcached,
        Self::Snmp,
        Self::Mqtt,
        Self::Vnc,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Redis => "redis",
            Self::Smtp => "smtp",
            Self::Pop3 => "pop3",
            Self::Imap => "imap",
            Self::Ssh => "ssh",
            Self::Ftp => "ftp",
            Self::Rdp => "rdp",
            Self::Telnet => "telnet",
            Self::Mysql => "mysql",
            Self::Postgresql => "postgresql",
            Self::Smb => "smb",
            Self::Ldap => "ldap",
            Self::Dns => "dns",
            Self::Mongodb => "mongodb",
            Self::Memcached => "memcached",
            Self::Snmp => "snmp",
            Self::Mqtt => "mqtt",
            Self::Vnc => "vnc",
        }
    }
}

impl std::str::FromStr for ProtocolId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == value)
            .ok_or_else(|| format!("unsupported simulation protocol: {value}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSpec {
    pub id: String,
    pub role: String,
    pub transport: TransportProtocol,
    pub container_port: u16,
    pub default_host_port: u16,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolFieldDescriptor {
    pub path: String,
    pub label_key: String,
    pub kind: String,
    pub required: bool,
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolDescriptor {
    pub protocol: ProtocolId,
    pub label: String,
    pub category: String,
    pub endpoints: Vec<EndpointSpec>,
    pub fields: Vec<ProtocolFieldDescriptor>,
    pub event_types: Vec<String>,
}

pub fn protocol_descriptors() -> Vec<ProtocolDescriptor> {
    ProtocolId::ALL
        .into_iter()
        .map(protocol_descriptor)
        .collect()
}

pub fn protocol_descriptor(protocol: ProtocolId) -> ProtocolDescriptor {
    let port = match protocol {
        ProtocolId::Http => 80,
        ProtocolId::Redis => 6379,
        ProtocolId::Smtp => 25,
        ProtocolId::Pop3 => 110,
        ProtocolId::Imap => 143,
        ProtocolId::Ssh => 22,
        ProtocolId::Ftp => 21,
        ProtocolId::Rdp => 3389,
        ProtocolId::Telnet => 23,
        ProtocolId::Mysql => 3306,
        ProtocolId::Postgresql => 5432,
        ProtocolId::Smb => 445,
        ProtocolId::Ldap => 389,
        ProtocolId::Dns => 53,
        ProtocolId::Mongodb => 27017,
        ProtocolId::Memcached => 11211,
        ProtocolId::Snmp => 161,
        ProtocolId::Mqtt => 1883,
        ProtocolId::Vnc => 5900,
    };
    let fields = match protocol {
        ProtocolId::Http => vec![field("server_header", "serverHeader", "text", false, false)],
        ProtocolId::Redis => vec![
            field("server_version", "serverVersion", "text", false, false),
            field("require_auth", "requireAuth", "boolean", false, false),
            field("password", "password", "text", false, true),
            field("keys", "keys", "key_value", false, false),
        ],
        ProtocolId::Smtp => vec![
            field("banner", "banner", "text", false, false),
            field("hostname", "hostname", "text", false, false),
            field("credentials", "credentials", "credentials", false, true),
        ],
        ProtocolId::Pop3 | ProtocolId::Imap => vec![
            field("banner", "banner", "text", false, false),
            field("credentials", "credentials", "credentials", false, true),
        ],
        ProtocolId::Rdp => vec![],
        ProtocolId::Mysql | ProtocolId::Postgresql => vec![
            field("server_version", "serverVersion", "text", false, false),
            field("credentials", "credentials", "credentials", false, true),
            field("databases", "databases", "string_list", false, false),
        ],
        ProtocolId::Smb => vec![
            field("server_name", "serverName", "text", false, false),
            field("domain", "domain", "text", false, false),
        ],
        ProtocolId::Ldap => vec![
            field("base_dn", "baseDn", "text", true, false),
            field("vendor_name", "vendorName", "text", false, false),
            field("vendor_version", "vendorVersion", "text", false, false),
        ],
        ProtocolId::Dns => vec![
            field("records", "dnsRecords", "key_value", true, false),
            field("default_ipv4", "defaultIpv4", "text", false, false),
            field("ttl", "ttl", "number", false, false),
            field("server_version", "serverVersion", "text", false, false),
            field("server_name", "serverName", "text", false, false),
        ],
        ProtocolId::Mongodb => vec![
            field("server_version", "serverVersion", "text", false, false),
            field("hostname", "hostname", "text", false, false),
            field("max_wire_version", "maxWireVersion", "number", false, false),
        ],
        ProtocolId::Memcached => vec![
            field("server_version", "serverVersion", "text", false, false),
            field("stats", "stats", "key_value", false, false),
        ],
        ProtocolId::Snmp => vec![
            field("community", "community", "text", false, true),
            field(
                "system_description",
                "systemDescription",
                "text",
                false,
                false,
            ),
            field("system_name", "systemName", "text", false, false),
            field("system_location", "systemLocation", "text", false, false),
            field("oids", "oids", "key_value", false, false),
        ],
        ProtocolId::Mqtt => vec![field(
            "allow_anonymous",
            "allowAnonymous",
            "boolean",
            false,
            false,
        )],
        ProtocolId::Vnc => vec![
            field("protocol_version", "protocolVersion", "text", false, false),
            field(
                "security_types",
                "securityTypes",
                "string_list",
                false,
                false,
            ),
        ],
        ProtocolId::Telnet => vec![
            field("banner", "banner", "text", false, false),
            field("prompt", "prompt", "text", false, false),
            field("credentials", "credentials", "credentials", false, true),
        ],
        ProtocolId::Ssh | ProtocolId::Ftp => vec![
            field("banner", "banner", "text", false, false),
            field("credentials", "credentials", "credentials", false, true),
        ],
    };
    let endpoints = match protocol {
        ProtocolId::Dns => vec![
            EndpointSpec {
                id: "dns-tcp".to_string(),
                role: "service".to_string(),
                transport: TransportProtocol::Tcp,
                container_port: 53,
                default_host_port: 1053,
                required: true,
            },
            EndpointSpec {
                id: "dns-udp".to_string(),
                role: "service".to_string(),
                transport: TransportProtocol::Udp,
                container_port: 53,
                default_host_port: 1053,
                required: true,
            },
        ],
        ProtocolId::Snmp => vec![EndpointSpec {
            id: "main".to_string(),
            role: "service".to_string(),
            transport: TransportProtocol::Udp,
            container_port: port,
            default_host_port: port,
            required: true,
        }],
        _ => vec![EndpointSpec {
            id: "main".to_string(),
            role: "service".to_string(),
            transport: TransportProtocol::Tcp,
            container_port: port,
            default_host_port: port,
            required: true,
        }],
    };
    let event_types = match protocol {
        ProtocolId::Mongodb => vec!["mongodb_command".to_string()],
        ProtocolId::Memcached => vec!["memcached_command".to_string()],
        ProtocolId::Snmp => vec!["snmp_query".to_string()],
        ProtocolId::Mqtt => vec!["mqtt_connect".to_string(), "mqtt_control".to_string()],
        ProtocolId::Vnc => vec!["vnc_handshake".to_string()],
        _ => vec![
            "connection".to_string(),
            "auth_attempt".to_string(),
            "command".to_string(),
            "query".to_string(),
            "exploit_attempt".to_string(),
        ],
    };
    ProtocolDescriptor {
        protocol,
        label: protocol.as_str().to_ascii_uppercase(),
        category: protocol_category(protocol).to_string(),
        endpoints,
        fields,
        event_types,
    }
}

const fn protocol_category(protocol: ProtocolId) -> &'static str {
    match protocol {
        ProtocolId::Redis
        | ProtocolId::Mysql
        | ProtocolId::Postgresql
        | ProtocolId::Mongodb
        | ProtocolId::Memcached => "database",
        ProtocolId::Smtp | ProtocolId::Pop3 | ProtocolId::Imap => "mail",
        ProtocolId::Smb | ProtocolId::Ldap => "enterprise",
        ProtocolId::Telnet
        | ProtocolId::Ssh
        | ProtocolId::Rdp
        | ProtocolId::Ftp
        | ProtocolId::Vnc => "remote_access",
        ProtocolId::Http => "web",
        ProtocolId::Dns | ProtocolId::Snmp => "network",
        ProtocolId::Mqtt => "messaging",
    }
}

fn field(
    path: &str,
    label_key: &str,
    kind: &str,
    required: bool,
    secret: bool,
) -> ProtocolFieldDescriptor {
    ProtocolFieldDescriptor {
        path: path.to_string(),
        label_key: label_key.to_string(),
        kind: kind.to_string(),
        required,
        secret,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundEndpoint {
    pub endpoint_id: String,
    pub transport: TransportProtocol,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineLaunchConfig {
    pub schema_version: u32,
    pub protocol: ProtocolId,
    pub rule_id: String,
    pub rule_name: String,
    pub instance_id: String,
    pub callback_url: String,
    pub callback_token: String,
    pub endpoints: Vec<BoundEndpoint>,
    pub behavior: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HttpExploitPathConfig {
    pub path: String,
    pub trigger_method: Option<String>,
    pub response_status: u16,
    pub response_body: String,
    pub response_headers: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimHttpConfig {
    pub server_header: Option<String>,
    pub headers: Option<BTreeMap<String, String>>,
    pub html: Option<String>,
    pub exploit_paths: Option<Vec<HttpExploitPathConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RedisCommandResponse {
    pub command: String,
    pub args_contains: Option<Vec<String>>,
    pub response: String,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SimRedisConfig {
    pub server_version: Option<String>,
    pub require_auth: Option<bool>,
    pub password: Option<String>,
    pub server_info: Option<BTreeMap<String, String>>,
    pub keys: Option<BTreeMap<String, String>>,
    pub command_responses: Option<Vec<RedisCommandResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MailCredential {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MailMessage {
    pub uid: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub date: Option<String>,
    pub body: String,
    pub flags: Option<Vec<String>>,
}

pub type Mailboxes = BTreeMap<String, Vec<MailMessage>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MailCustomResponse {
    pub command: String,
    pub args_contains: Option<Vec<String>>,
    pub response: String,
    pub event_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimSmtpConfig {
    pub banner: Option<String>,
    pub hostname: Option<String>,
    pub require_auth: Option<bool>,
    pub credentials: Option<Vec<MailCredential>>,
    pub capabilities: Option<Vec<String>>,
    pub accepted_recipients: Option<Vec<String>>,
    pub custom_responses: Option<Vec<MailCustomResponse>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimPop3Config {
    pub banner: Option<String>,
    pub require_auth: Option<bool>,
    pub credentials: Option<Vec<MailCredential>>,
    pub capabilities: Option<Vec<String>>,
    pub messages: Option<Vec<MailMessage>>,
    pub custom_responses: Option<Vec<MailCustomResponse>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimImapConfig {
    pub banner: Option<String>,
    pub require_auth: Option<bool>,
    pub credentials: Option<Vec<MailCredential>>,
    pub capabilities: Option<Vec<String>>,
    pub mailboxes: Option<Mailboxes>,
    pub messages: Option<Vec<MailMessage>>,
    pub custom_responses: Option<Vec<MailCustomResponse>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimSshConfig {
    pub banner: Option<String>,
    pub credentials: Option<Vec<Credential>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimFtpConfig {
    pub banner: Option<String>,
    pub credentials: Option<Vec<Credential>>,
    pub server_name: Option<String>,
    pub allow_anonymous: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SimRdpConfig {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimTelnetConfig {
    pub banner: Option<String>,
    pub prompt: Option<String>,
    pub credentials: Option<Vec<Credential>>,
    pub command_responses: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimDatabaseConfig {
    pub server_version: Option<String>,
    pub credentials: Option<Vec<Credential>>,
    pub databases: Option<Vec<String>>,
    pub query_responses: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SimSmbConfig {
    pub server_name: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SimLdapConfig {
    pub base_dn: String,
    pub vendor_name: Option<String>,
    pub vendor_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SimDnsConfig {
    pub server_version: Option<String>,
    pub server_name: Option<String>,
    pub records: BTreeMap<String, String>,
    pub default_ipv4: Option<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimMongodbConfig {
    pub server_version: Option<String>,
    pub hostname: Option<String>,
    pub max_wire_version: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimMemcachedConfig {
    pub server_version: Option<String>,
    pub stats: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimSnmpConfig {
    pub community: Option<String>,
    pub system_description: Option<String>,
    pub system_name: Option<String>,
    pub system_location: Option<String>,
    pub oids: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimMqttConfig {
    pub allow_anonymous: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SimVncConfig {
    pub protocol_version: Option<String>,
    pub security_types: Option<Vec<String>>,
}

pub fn validate_behavior(protocol: ProtocolId, value: Value) -> Result<Value, serde_json::Error> {
    use serde::de::Error;
    let invalid = |message: &str| serde_json::Error::custom(message);
    if let Some(banner) = value.get("banner").and_then(Value::as_str) {
        if banner.contains(['\r', '\n', '\0']) {
            return Err(invalid(
                "banner must be a single line without control terminators",
            ));
        }
        let prefix = match protocol {
            ProtocolId::Smtp | ProtocolId::Ftp => "220",
            ProtocolId::Pop3 => "+OK",
            ProtocolId::Imap => "* OK",
            _ => "",
        };
        if !prefix.is_empty() && banner.to_ascii_uppercase().starts_with(prefix) {
            return Err(invalid(
                "banner must contain greeting text without the protocol status prefix",
            ));
        }
        if protocol == ProtocolId::Ssh && (!banner.starts_with("SSH-2.0-") || banner.len() > 253) {
            return Err(invalid(
                "SSH banner must be a valid SSH-2.0 identification line",
            ));
        }
    }
    if let Some(version) = value.get("server_version").and_then(Value::as_str)
        && (version.is_empty() || version.contains(['\r', '\n', '\0']))
    {
        return Err(invalid("server_version must be a non-empty single line"));
    }
    for key in [
        "server_name",
        "domain",
        "vendor_name",
        "vendor_version",
        "hostname",
        "server_header",
    ] {
        if let Some(text) = value.get(key).and_then(Value::as_str)
            && (text.is_empty() || text.len() > 255 || text.chars().any(char::is_control))
        {
            return Err(invalid(
                "service identity must be a non-empty single line of at most 255 bytes",
            ));
        }
    }
    for key in ["server_info", "stats", "oids"] {
        if let Some(fields) = value.get(key).and_then(Value::as_object) {
            for (name, text) in fields {
                if name.is_empty()
                    || name
                        .chars()
                        .any(|ch| ch.is_whitespace() || ch == ':' || ch.is_control())
                    || text
                        .as_str()
                        .is_some_and(|v| v.chars().any(char::is_control))
                {
                    return Err(invalid(
                        "identity map contains invalid field names or control characters",
                    ));
                }
            }
        }
    }
    if protocol == ProtocolId::Dns {
        for key in ["server_version", "server_name"] {
            if value
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|v| v.len() > 255)
            {
                return Err(invalid("DNS identity TXT value exceeds 255 bytes"));
            }
        }
    }
    match protocol {
        ProtocolId::Http => round_trip::<SimHttpConfig>(value),
        ProtocolId::Redis => round_trip::<SimRedisConfig>(value),
        ProtocolId::Smtp => round_trip::<SimSmtpConfig>(value),
        ProtocolId::Pop3 => round_trip::<SimPop3Config>(value),
        ProtocolId::Imap => round_trip::<SimImapConfig>(value),
        ProtocolId::Ssh => round_trip::<SimSshConfig>(value),
        ProtocolId::Ftp => round_trip::<SimFtpConfig>(value),
        ProtocolId::Rdp => round_trip::<SimRdpConfig>(value),
        ProtocolId::Telnet => round_trip::<SimTelnetConfig>(value),
        ProtocolId::Mysql | ProtocolId::Postgresql => round_trip::<SimDatabaseConfig>(value),
        ProtocolId::Smb => round_trip::<SimSmbConfig>(value),
        ProtocolId::Ldap => round_trip::<SimLdapConfig>(value),
        ProtocolId::Dns => round_trip::<SimDnsConfig>(value),
        ProtocolId::Mongodb => round_trip::<SimMongodbConfig>(value),
        ProtocolId::Memcached => round_trip::<SimMemcachedConfig>(value),
        ProtocolId::Snmp => round_trip::<SimSnmpConfig>(value),
        ProtocolId::Mqtt => round_trip::<SimMqttConfig>(value),
        ProtocolId::Vnc => round_trip::<SimVncConfig>(value),
    }
}

fn round_trip<T>(value: Value) -> Result<Value, serde_json::Error>
where
    T: Serialize + serde::de::DeserializeOwned,
{
    serde_json::to_value(serde_json::from_value::<T>(value)?)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_EVENT_CALLBACK_URL, ProtocolId, protocol_descriptor, protocol_descriptors,
        validate_behavior,
    };

    #[test]
    fn default_event_callback_uses_compose_service_dns_name() {
        assert_eq!(
            DEFAULT_EVENT_CALLBACK_URL,
            "http://veydeck-protocol-simulation:8080/internal/events"
        );
    }

    #[test]
    fn v1_capabilities_cover_all_supported_protocols_with_named_endpoints() {
        let descriptors = protocol_descriptors();
        assert_eq!(descriptors.len(), ProtocolId::ALL.len());
        assert!(descriptors.iter().all(|descriptor| {
            !descriptor.endpoints.is_empty()
                && descriptor
                    .endpoints
                    .iter()
                    .all(|endpoint| !endpoint.id.is_empty() && endpoint.container_port > 0)
        }));
    }

    #[test]
    fn ldap_behavior_requires_base_dn_in_v1() {
        assert!(validate_behavior(ProtocolId::Ldap, serde_json::json!({})).is_err());
        assert!(
            validate_behavior(
                ProtocolId::Ldap,
                serde_json::json!({"base_dn": "dc=lab,dc=example"}),
            )
            .is_ok()
        );
    }

    #[test]
    fn telnet_capability_exposes_prompt_in_v1() {
        let descriptor = protocol_descriptor(ProtocolId::Telnet);
        assert!(
            descriptor
                .fields
                .iter()
                .any(|field| field.path == "prompt" && field.kind == "text")
        );
    }

    #[test]
    fn dns_capability_exposes_tcp_and_udp_endpoints_in_v1() {
        let descriptor = protocol_descriptor(ProtocolId::Dns);
        assert_eq!(descriptor.endpoints.len(), 2);
        assert_eq!(descriptor.endpoints[0].id, "dns-tcp");
        assert_eq!(descriptor.endpoints[1].id, "dns-udp");
        assert_eq!(descriptor.endpoints[0].default_host_port, 1053);
        assert_eq!(descriptor.endpoints[1].default_host_port, 1053);
    }

    #[test]
    fn snmp_capability_exposes_a_udp_endpoint_in_v1() {
        let descriptor = protocol_descriptor(ProtocolId::Snmp);
        assert_eq!(descriptor.endpoints.len(), 1);
        assert_eq!(descriptor.endpoints[0].id, "main");
        assert_eq!(descriptor.endpoints[0].transport.as_str(), "udp");
        assert_eq!(descriptor.endpoints[0].container_port, 161);
        assert_eq!(descriptor.endpoints[0].default_host_port, 161);
    }
    #[test]
    fn greeting_configuration_is_body_only_and_single_line() {
        use serde_json::json;
        for (protocol, prefix) in [
            (ProtocolId::Smtp, "220 mail"),
            (ProtocolId::Pop3, "+OK ready"),
            (ProtocolId::Imap, "* OK ready"),
            (ProtocolId::Ftp, "220 ready"),
        ] {
            assert!(validate_behavior(protocol, json!({"banner": prefix})).is_err());
            assert!(validate_behavior(protocol, json!({"banner": "ready"})).is_ok());
            assert!(validate_behavior(protocol, json!({"banner": "ready\r\nforged"})).is_err());
        }
        assert!(
            validate_behavior(ProtocolId::Ssh, json!({"banner":"SSH-2.0-OpenSSH_9.6"})).is_ok()
        );
        assert!(validate_behavior(ProtocolId::Ssh, json!({"banner":"OpenSSH_9.6"})).is_err());
    }
    #[test]
    fn removed_fields_are_rejected_and_identity_fields_round_trip() {
        use serde_json::json;
        for (protocol, value) in [
            (ProtocolId::Redis, json!({"banner":"ready"})),
            (ProtocolId::Rdp, json!({"flags":1})),
            (ProtocolId::Smb, json!({"shares":[]})),
            (ProtocolId::Ldap, json!({"base_dn":"dc=test", "entries":[]})),
        ] {
            assert!(validate_behavior(protocol, value).is_err());
        }
        let ldap = validate_behavior(
            ProtocolId::Ldap,
            json!({"base_dn":"dc=test", "vendor_name":"OpenLDAP", "vendor_version":"2.6.8"}),
        )
        .unwrap();
        assert_eq!(ldap["vendor_version"], "2.6.8");
        assert!(
            validate_behavior(
                ProtocolId::Dns,
                json!({"records":{}, "server_version":"x".repeat(256)})
            )
            .is_err()
        );
        assert!(
            validate_behavior(
                ProtocolId::Redis,
                json!({"server_info":{"redis_version":"1\r\nforged"}})
            )
            .is_err()
        );
    }
}
