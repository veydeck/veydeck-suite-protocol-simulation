use super::Config;
use anyhow::Context;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::fmt;
use veydeck_suite_runtime::{OperationEvent, RuntimeClient};

#[derive(Clone)]
pub struct AgentClient {
    config: Config,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWorkloadRequest {
    pub workload_kind: String,
    pub workload_name: String,
    pub image: String,
    pub ports: Vec<WorkloadPort>,
    pub env: serde_json::Value,
    pub config_json: serde_json::Value,
    pub resources: WorkloadResources,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadPort {
    pub endpoint_id: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: WorkloadTransport,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadResources {
    pub memory_mb: u32,
    pub cpu_shares: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartWorkloadResponse {
    pub workload_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentErrorEnvelope {
    message: String,
    error_code: Option<String>,
    data: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct AgentApiError {
    status: reqwest::StatusCode,
    code: Option<String>,
    message: String,
    detail: Option<serde_json::Value>,
}

impl AgentApiError {
    pub fn is_port_unavailable(&self) -> bool {
        self.status == reqwest::StatusCode::CONFLICT
            && self.code.as_deref() == Some("SUITE_WORKLOAD_PORT_UNAVAILABLE")
    }
}

impl fmt::Display for AgentApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Agent suite runtime request failed: {}: {}",
            self.status, self.message
        )?;
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AgentApiError {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartPcapResponse {
    pub capture_id: String,
    #[serde(default)]
    pub endpoints: Vec<CaptureEndpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEndpoint {
    pub endpoint_id: String,
    pub host_port: u16,
    pub protocol: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSummary {
    pub workload_id: String,
    pub suite_instance_id: String,
}

impl AgentClient {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn start_workload(
        &self,
        payload: &StartWorkloadRequest,
    ) -> anyhow::Result<StartWorkloadResponse> {
        let runtime = self.runtime_client("workloads.manage").await?;
        let response = runtime
            .request(
                Method::POST,
                "/api/v1/agent/suite-runtime/workloads",
                Some(payload),
            )
            .await
            .map_err(runtime_error)?;
        response
            .json::<StartWorkloadResponse>()
            .await
            .context("invalid Agent suite workload start response")
    }

    /// 读取 Agent 注入的 v1 runtime 描述中的平台版本，用于规则包最低版本校验。
    pub async fn platform_version(&self) -> anyhow::Result<semver::Version> {
        let content = tokio::fs::read_to_string(&self.config.agent_runtime_path)
            .await
            .with_context(|| {
                format!(
                    "failed to read Agent runtime descriptor {}",
                    self.config.agent_runtime_path.display()
                )
            })?;
        let value = serde_json::from_str::<serde_json::Value>(&content)
            .context("invalid Agent runtime descriptor JSON")?;
        let version = value
            .get("platformVersion")
            .and_then(serde_json::Value::as_str)
            .context("Agent runtime descriptor is missing platformVersion")?;
        semver::Version::parse(version).context("Agent platformVersion is invalid")
    }

    pub async fn stop_workload(&self, workload_id: &str) -> anyhow::Result<()> {
        let runtime = self.runtime_client("workloads.manage").await?;
        runtime
            .request::<serde_json::Value>(
                Method::DELETE,
                &format!("/api/v1/agent/suite-runtime/workloads/{workload_id}"),
                None,
            )
            .await
            .map_err(runtime_error)?;
        Ok(())
    }

    pub async fn start_pcap(&self, workload_id: &str) -> anyhow::Result<StartPcapResponse> {
        let runtime = self.runtime_client("captures.manage").await?;
        let response = runtime
            .request::<serde_json::Value>(
                Method::POST,
                &format!("/api/v1/agent/suite-runtime/workloads/{workload_id}/captures"),
                None,
            )
            .await
            .map_err(runtime_error)?;
        response
            .json::<StartPcapResponse>()
            .await
            .context("invalid Agent suite pcap start response")
    }

    pub async fn stop_pcap(&self, workload_id: &str, capture_id: &str) -> anyhow::Result<Vec<u8>> {
        let runtime = self.runtime_client("captures.manage").await?;
        let response = runtime
            .request::<serde_json::Value>(
                Method::POST,
                &format!(
                    "/api/v1/agent/suite-runtime/workloads/{workload_id}/captures/{capture_id}/finish"
                ),
                None,
            )
            .await
            .map_err(runtime_error)?;
        Ok(response
            .bytes()
            .await
            .context("invalid Agent suite pcap payload")?
            .to_vec())
    }

    pub async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadSummary>> {
        let runtime = self.runtime_client("workloads.manage").await?;
        let response = runtime
            .request::<serde_json::Value>(
                Method::GET,
                "/api/v1/agent/suite-runtime/workloads",
                None,
            )
            .await
            .map_err(runtime_error)?;
        response
            .json::<Vec<WorkloadSummary>>()
            .await
            .context("invalid Agent suite workload list response")
    }

    async fn runtime_client(&self, capability: &str) -> anyhow::Result<RuntimeClient> {
        RuntimeClient::from_path(&self.config.agent_runtime_path, capability)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn submit_operation_event(&self, event: &OperationEvent) -> anyhow::Result<()> {
        self.runtime_client("operation-logs.write")
            .await?
            .submit_operation_event(event)
            .await
            .map_err(anyhow::Error::from)
    }
}

fn runtime_error(error: veydeck_suite_runtime::Error) -> anyhow::Error {
    let veydeck_suite_runtime::Error::Agent { status, message } = error else {
        return anyhow::Error::new(error);
    };
    let envelope = serde_json::from_str::<AgentErrorEnvelope>(&message).ok();
    anyhow::Error::new(AgentApiError {
        status: reqwest::StatusCode::from_u16(status)
            .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
        code: envelope.as_ref().and_then(|body| body.error_code.clone()),
        message: envelope
            .as_ref()
            .map(|body| body.message.clone())
            .filter(|value| !value.is_empty())
            .unwrap_or(message),
        detail: envelope.and_then(|body| body.data),
    })
}

#[cfg(test)]
mod tests {
    use veydeck_suite_runtime::{RuntimeDescriptor, RuntimeEndpoint};

    #[test]
    fn runtime_descriptor_supports_unix_and_https_endpoints() {
        let unix = serde_json::from_str::<RuntimeDescriptor>(
            r#"{
                "schemaVersion": 1,
                "platformVersion": "0.1.0-alpha.1",
                "suiteId": "suite.example",
                "instanceId": "instance-1",
                "endpoint": {
                    "kind": "unix",
                    "socketPath": "/run/veydeck-agent.sock",
                    "baseUrl": "http://local"
                },
                "credential": {"tokenPath": "/run/veydeck-agent/access-token"},
                "capabilities": ["workloads.manage"]
            }"#,
        )
        .unwrap();
        assert!(matches!(unix.endpoint, RuntimeEndpoint::Unix { .. }));

        let https = serde_json::from_str::<RuntimeDescriptor>(
            r#"{
                "schemaVersion": 1,
                "platformVersion": "0.1.0-alpha.1",
                "suiteId": "suite.example",
                "instanceId": "instance-1",
                "endpoint": {
                    "kind": "https",
                    "baseUrl": "https://host.docker.internal:7311",
                    "caPath": "/run/veydeck-agent/agent-ca.crt",
                    "clientCertPath": "/run/veydeck-agent/agent-client.crt",
                    "clientKeyPath": "/run/veydeck-agent/agent-client.key"
                },
                "credential": {"tokenPath": "/run/veydeck-agent/access-token"},
                "capabilities": ["captures.manage"]
            }"#,
        )
        .unwrap();
        assert!(matches!(https.endpoint, RuntimeEndpoint::Https { .. }));
    }
}
