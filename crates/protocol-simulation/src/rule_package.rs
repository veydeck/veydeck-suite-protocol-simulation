use anyhow::{Context, bail};
use base64::Engine;
use flate2::read::GzDecoder;
use prost::Message;
use protocol_simulation_common::{ProtocolId, protocol_descriptor, validate_behavior};
use ring::signature;
use serde_json::json;
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::str::FromStr;

const RULESET_FORMAT_VERSION: i32 = 1;
const PACKAGE_SCHEMA_VERSION: i32 = 1;
const MAX_RULES_BIN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 32 * 1024;
const MAX_RULE_COUNT: usize = 100_000;
const DEFAULT_RULES_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXkgRkI0OENFRkMyRDU5NEQxQgpSV1FiVFZrdC9NNUkreFQ1dktRL3BUaitaOXFaU1hKYVZOQUNtMmFQRjVCaEozZXdGQVRaY0pQdwo=";

#[derive(Clone, PartialEq, Message)]
pub struct SimRuleProto {
    #[prost(int64, tag = "1")]
    pub id: i64,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub name_en: String,
    #[prost(string, optional, tag = "4")]
    pub cve: Option<String>,
    #[prost(string, tag = "5")]
    pub category: String,
    #[prost(string, tag = "6")]
    pub description_zh: String,
    #[prost(string, tag = "7")]
    pub description_en: String,
    #[prost(string, tag = "8")]
    pub protocol: String,
    #[prost(int64, optional, tag = "9")]
    pub default_port: Option<i64>,
    #[prost(string, tag = "10")]
    pub config_json: String,
    #[prost(message, repeated, tag = "11")]
    pub endpoints: Vec<RuleEndpointProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RuleEndpointProto {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub transport: String,
    #[prost(int32, tag = "3")]
    pub container_port: i32,
    #[prost(int32, tag = "4")]
    pub default_host_port: i32,
    #[prost(bool, tag = "5")]
    pub required: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct RulePackageManifestProto {
    #[prost(string, tag = "1")]
    pub package_id: String,
    #[prost(string, tag = "2")]
    pub version: String,
    #[prost(int32, tag = "3")]
    pub ruleset_format_version: i32,
    #[prost(string, tag = "4")]
    pub min_veydeck_version: String,
    #[prost(int64, tag = "5")]
    pub generated_at: i64,
    #[prost(int32, tag = "6")]
    pub rule_count: i32,
    #[prost(int32, tag = "7")]
    pub schema_version: i32,
    /// 消费规则包的套件标识。
    #[prost(string, tag = "8")]
    pub suite_id: String,
    /// 套件业务资产类型。
    #[prost(string, tag = "9")]
    pub package_type: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct SimRulePackageProto {
    #[prost(message, optional, tag = "1")]
    pub manifest: Option<RulePackageManifestProto>,
    #[prost(message, repeated, tag = "2")]
    pub rules: Vec<SimRuleProto>,
}

#[derive(Debug, Clone)]
pub struct ImportedRule {
    pub id: String,
    pub name: String,
    pub name_en: String,
    pub protocol: String,
    pub default_port: u16,
    pub config_json: String,
}

#[derive(Debug, Clone)]
pub struct ImportedRulePackage {
    pub package_id: String,
    pub version: String,
    pub ruleset_format_version: i64,
    pub min_veydeck_version: String,
    pub generated_at: String,
    pub rules: Vec<ImportedRule>,
}

pub fn parse_rule_package(bytes: &[u8]) -> anyhow::Result<ImportedRulePackage> {
    let public_key = std::env::var("VEYDECK_SIM_RULES_PUBLIC_KEY")
        .unwrap_or_else(|_| DEFAULT_RULES_PUBLIC_KEY.to_string());
    parse_rule_package_with_public_key(bytes, &public_key)
}

fn parse_rule_package_with_public_key(
    bytes: &[u8],
    public_key_text: &str,
) -> anyhow::Result<ImportedRulePackage> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
    let mut rules_bin = None;
    let mut signature_text = None;
    let mut seen_entries = HashSet::new();

    for entry in archive
        .entries()
        .context("failed to read rule package archive")?
    {
        let entry = entry.context("failed to read rule package entry")?;
        let path = entry
            .path()
            .context("failed to read rule package entry path")?
            .to_string_lossy()
            .replace('\\', "/");
        if !seen_entries.insert(path.clone()) {
            bail!("duplicate rule package entry: {path}");
        }
        if !entry.header().entry_type().is_file() {
            bail!("rule package entry is not a regular file: {path}");
        }
        if path == "rules.bin" {
            let mut content = Vec::new();
            entry
                .take(MAX_RULES_BIN_BYTES + 1)
                .read_to_end(&mut content)
                .context("failed to read rules.bin")?;
            if content.len() as u64 > MAX_RULES_BIN_BYTES {
                bail!("rules.bin exceeds the v1 size limit");
            }
            rules_bin = Some(content);
        } else if path == "rules.bin.sig" {
            let mut content = String::new();
            entry
                .take(MAX_SIGNATURE_BYTES + 1)
                .read_to_string(&mut content)
                .context("failed to read rules.bin.sig")?;
            if content.len() as u64 > MAX_SIGNATURE_BYTES {
                bail!("rules.bin.sig exceeds the v1 size limit");
            }
            signature_text = Some(content);
        } else {
            bail!("unexpected rule package entry: {path}");
        }
    }

    let Some(rules_bin) = rules_bin else {
        bail!("rules.bin is missing from rule package");
    };
    let signature_text = signature_text.context("rules.bin.sig is missing from rule package")?;
    verify_detached_signature(public_key_text, &rules_bin, &signature_text)
        .context("rule package signature verification failed")?;

    let package = SimRulePackageProto::decode(rules_bin.as_slice())
        .context("failed to decode rule package payload")?;
    let manifest = package
        .manifest
        .context("rule package manifest is missing")?;
    if manifest.schema_version != PACKAGE_SCHEMA_VERSION {
        bail!(
            "unsupported rule package schemaVersion: {}",
            manifest.schema_version
        );
    }
    if manifest.ruleset_format_version != RULESET_FORMAT_VERSION {
        bail!(
            "unsupported rulesetFormatVersion: {} (only v1 is supported during alpha)",
            manifest.ruleset_format_version
        );
    }
    if manifest.rule_count != package.rules.len() as i32 {
        bail!(
            "rule package manifest declares {} rules but payload contains {}",
            manifest.rule_count,
            package.rules.len()
        );
    }
    if package.rules.len() > MAX_RULE_COUNT {
        bail!("rule package exceeds the v1 rule count limit");
    }
    if package.rules.is_empty() {
        bail!("rule package must contain at least one rule");
    }
    if manifest.package_id != "veydeck-sim-rules" {
        bail!("unsupported rule package id: {}", manifest.package_id);
    }
    if manifest.suite_id != "veydeck.protocol-simulation" {
        bail!("unsupported rule package suiteId: {}", manifest.suite_id);
    }
    if manifest.package_type != "protocol-simulation-rules" {
        bail!(
            "unsupported rule package packageType: {}",
            manifest.package_type
        );
    }
    semver::Version::parse(&manifest.version).context("rule package version is invalid")?;
    semver::Version::parse(&manifest.min_veydeck_version)
        .context("rule package minVeydeckVersion is invalid")?;

    let generated_at = chrono::DateTime::from_timestamp(manifest.generated_at, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();
    let mut rules = Vec::with_capacity(package.rules.len());
    let mut rule_ids = HashSet::new();
    for rule in package.rules {
        if !(1..1_000_000).contains(&rule.id) {
            bail!("rule {} is outside the official v1 ID partition", rule.id);
        }
        if !rule_ids.insert(rule.id) {
            bail!("duplicate rule id: {}", rule.id);
        }
        let protocol = ProtocolId::from_str(&rule.protocol).map_err(anyhow::Error::msg)?;
        let descriptor = protocol_descriptor(protocol);
        validate_rule_endpoints(&rule, &descriptor.endpoints)?;
        let default_port = default_rule_host_port(&rule)
            .context("rule does not contain a valid default host port")?;
        let behavior = serde_json::from_str::<serde_json::Value>(&rule.config_json)
            .with_context(|| format!("rule {} config_json is invalid JSON", rule.id))?;
        let behavior = validate_behavior(protocol, behavior)
            .with_context(|| format!("rule {} behavior does not match protocol schema", rule.id))?;
        let config_json = serde_json::to_string_pretty(&json!({
            "nameEn": rule.name_en.clone(),
            "category": rule.category,
            "cve": rule.cve,
            "description": rule.description_zh,
            "descriptionEn": rule.description_en,
            "behavior": behavior
        }))?;
        rules.push(ImportedRule {
            id: format!("sim-rule-{}", rule.id),
            name: rule.name,
            name_en: rule.name_en,
            protocol: rule.protocol,
            default_port,
            config_json,
        });
    }

    Ok(ImportedRulePackage {
        package_id: manifest.package_id,
        version: manifest.version,
        ruleset_format_version: i64::from(manifest.ruleset_format_version),
        min_veydeck_version: manifest.min_veydeck_version,
        generated_at,
        rules,
    })
}

fn default_rule_host_port(rule: &SimRuleProto) -> Option<u16> {
    rule.default_port
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| {
            rule.endpoints
                .iter()
                .find(|endpoint| endpoint.id == "main")
                .or_else(|| rule.endpoints.first())
                .and_then(|endpoint| u16::try_from(endpoint.default_host_port).ok())
        })
}

fn validate_rule_endpoints(
    rule: &SimRuleProto,
    expected: &[protocol_simulation_common::EndpointSpec],
) -> anyhow::Result<()> {
    if rule.endpoints.len() != expected.len() {
        bail!(
            "rule {} endpoint declaration does not match protocol descriptor",
            rule.id
        );
    }
    for endpoint in expected {
        let actual = rule
            .endpoints
            .iter()
            .find(|candidate| candidate.id == endpoint.id)
            .with_context(|| format!("rule {} is missing endpoint {}", rule.id, endpoint.id))?;
        if actual.transport != endpoint.transport.as_str()
            || actual.container_port != i32::from(endpoint.container_port)
            || actual.required != endpoint.required
            || u16::try_from(actual.default_host_port).is_err()
        {
            bail!("rule {} endpoint {} is invalid", rule.id, endpoint.id);
        }
    }
    Ok(())
}

fn verify_detached_signature(
    public_key_text: &str,
    message: &[u8],
    signature_text: &str,
) -> anyhow::Result<()> {
    let public_key = decode_public_key(public_key_text)?;
    let (signature, prehashed) = decode_signature(signature_text)?;
    let verified_message = if prehashed {
        blake2b_simd::Params::new()
            .hash_length(64)
            .hash(message)
            .as_bytes()
            .to_vec()
    } else {
        message.to_vec()
    };
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&verified_message, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 signature is invalid"))
}

fn decode_public_key(text: &str) -> anyhow::Result<Vec<u8>> {
    let payload = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("untrusted comment:"))
        .context("public key payload is missing")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(payload)?;
    if let Ok(nested) = std::str::from_utf8(&decoded)
        && nested.contains("minisign public key")
    {
        return decode_public_key(nested);
    }
    match decoded.len() {
        32 => Ok(decoded),
        42 if decoded.starts_with(b"Ed") || decoded.starts_with(b"ED") => {
            Ok(decoded[10..].to_vec())
        }
        _ => bail!("public key payload is invalid"),
    }
}

fn decode_signature(text: &str) -> anyhow::Result<(Vec<u8>, bool)> {
    let payload = text
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with("untrusted comment:")
                && !line.starts_with("trusted comment:")
        })
        .context("signature payload is missing")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(payload)?;
    match decoded.len() {
        64 => Ok((decoded, false)),
        length if length >= 74 && decoded.starts_with(b"Ed") => {
            Ok((decoded[10..74].to_vec(), false))
        }
        length if length >= 74 && decoded.starts_with(b"ED") => {
            Ok((decoded[10..74].to_vec(), true))
        }
        _ => bail!("signature payload is invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use ring::signature::KeyPair;
    use tar::Builder;

    #[test]
    fn parse_rule_package_decodes_rules_payload() {
        let random = ring::rand::SystemRandom::new();
        let document = signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let package = SimRulePackageProto {
            manifest: Some(RulePackageManifestProto {
                package_id: "veydeck-sim-rules".to_string(),
                suite_id: "veydeck.protocol-simulation".to_string(),
                package_type: "protocol-simulation-rules".to_string(),
                version: "0.1.0-alpha.1".to_string(),
                ruleset_format_version: 1,
                min_veydeck_version: "0.1.0-alpha.1".to_string(),
                generated_at: 1_700_000_000,
                rule_count: 1,
                schema_version: 1,
            }),
            rules: vec![SimRuleProto {
                id: 100001,
                name: "测试规则".to_string(),
                name_en: "Test Rule".to_string(),
                cve: Some("CVE-2024-0001".to_string()),
                category: "cve_sim".to_string(),
                description_zh: "描述".to_string(),
                description_en: "Description".to_string(),
                protocol: "http".to_string(),
                default_port: Some(8080),
                config_json: r#"{"html":"ok"}"#.to_string(),
                endpoints: vec![RuleEndpointProto {
                    id: "main".to_string(),
                    transport: "tcp".to_string(),
                    container_port: 80,
                    default_host_port: 8080,
                    required: true,
                }],
            }],
        };
        let mut payload = Vec::new();
        package.encode(&mut payload).unwrap();
        let signature =
            base64::engine::general_purpose::STANDARD.encode(key_pair.sign(&payload).as_ref());
        let mut archive_bytes = Vec::new();
        {
            let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
            let mut tar = Builder::new(encoder);
            append_bytes(&mut tar, "rules.bin", &payload);
            append_bytes(&mut tar, "rules.bin.sig", signature.as_bytes());
            tar.finish().unwrap();
        }

        let public_key =
            base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
        assert!(
            verify_detached_signature(&public_key, b"tampered", &signature).is_err(),
            "a detached signature must not verify a modified rules.bin"
        );
        let parsed = parse_rule_package_with_public_key(&archive_bytes, &public_key).unwrap();

        assert_eq!(parsed.package_id, "veydeck-sim-rules");
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].id, "sim-rule-100001");
        assert_eq!(parsed.rules[0].name, "测试规则");
        assert_eq!(parsed.rules[0].name_en, "Test Rule");
        assert!(
            parsed.rules[0]
                .config_json
                .contains(r#""nameEn": "Test Rule""#)
        );
        assert!(parsed.rules[0].config_json.contains("CVE-2024-0001"));
    }

    #[test]
    fn dns_rule_uses_legacy_default_port_without_a_main_endpoint() {
        let rule = SimRuleProto {
            id: 507001,
            protocol: "dns".to_string(),
            default_port: Some(1053),
            endpoints: vec![
                RuleEndpointProto {
                    id: "dns-tcp".to_string(),
                    transport: "tcp".to_string(),
                    container_port: 53,
                    default_host_port: 1053,
                    required: true,
                },
                RuleEndpointProto {
                    id: "dns-udp".to_string(),
                    transport: "udp".to_string(),
                    container_port: 53,
                    default_host_port: 1053,
                    required: true,
                },
            ],
            ..Default::default()
        };
        assert_eq!(default_rule_host_port(&rule), Some(1053));
    }

    #[test]
    fn parse_rule_package_rejects_missing_or_unrelated_package_identity() {
        for (suite_id, package_type, expected_error) in [
            ("veydeck.packet", "protocol-simulation-rules", "suiteId"),
            ("", "protocol-simulation-rules", "suiteId"),
            ("veydeck.protocol-simulation", "packet-rules", "packageType"),
            ("veydeck.protocol-simulation", "", "packageType"),
        ] {
            let package = SimRulePackageProto {
                manifest: Some(RulePackageManifestProto {
                    package_id: "veydeck-sim-rules".to_string(),
                    suite_id: suite_id.to_string(),
                    package_type: package_type.to_string(),
                    version: "0.1.0-alpha.1".to_string(),
                    ruleset_format_version: 1,
                    min_veydeck_version: "0.1.0-alpha.1".to_string(),
                    generated_at: 1_700_000_000,
                    rule_count: 1,
                    schema_version: 1,
                }),
                rules: vec![SimRuleProto::default()],
            };
            let random = ring::rand::SystemRandom::new();
            let document = signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
            let payload = package.encode_to_vec();
            let signature =
                base64::engine::general_purpose::STANDARD.encode(key_pair.sign(&payload).as_ref());
            let mut archive_bytes = Vec::new();
            {
                let encoder = GzEncoder::new(&mut archive_bytes, Compression::default());
                let mut tar = Builder::new(encoder);
                append_bytes(&mut tar, "rules.bin", &payload);
                append_bytes(&mut tar, "rules.bin.sig", signature.as_bytes());
                tar.finish().unwrap();
            }
            let public_key =
                base64::engine::general_purpose::STANDARD.encode(key_pair.public_key().as_ref());
            let error =
                parse_rule_package_with_public_key(&archive_bytes, &public_key).unwrap_err();
            assert!(error.to_string().contains(expected_error), "{error:#}");
        }
    }

    fn append_bytes<W: std::io::Write>(tar: &mut Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, bytes).unwrap();
    }
}
