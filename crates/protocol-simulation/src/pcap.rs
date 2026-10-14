use anyhow::{Context, bail};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct OrphanCleanupReport {
    pub removed: usize,
    pub failures: Vec<(String, String)>,
}

pub fn capture_file_name(instance_id: &str) -> String {
    format!("pcap_{instance_id}.pcap")
}

pub async fn remove_capture_file(data_dir: &Path, file_name: Option<&str>) -> anyhow::Result<bool> {
    let Some(file_name) = file_name else {
        return Ok(false);
    };
    let path = capture_file_path(data_dir, file_name)?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove pcap file {}", path.display()))
        }
    }
}

pub async fn cleanup_orphaned_capture_files(
    data_dir: &Path,
    referenced_files: &HashSet<String>,
) -> anyhow::Result<OrphanCleanupReport> {
    let pcap_dir = data_dir.join("pcap");
    let mut entries = match tokio::fs::read_dir(&pcap_dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(OrphanCleanupReport::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read pcap directory {}", pcap_dir.display()));
        }
    };
    let mut report = OrphanCleanupReport::default();
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if referenced_files.contains(file_name)
            || !is_managed_capture_file(file_name)
            || !entry.file_type().await?.is_file()
        {
            continue;
        }
        match tokio::fs::remove_file(entry.path()).await {
            Ok(()) => report.removed += 1,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => report
                .failures
                .push((file_name.to_string(), error.to_string())),
        }
    }
    Ok(report)
}

fn capture_file_path(data_dir: &Path, file_name: &str) -> anyhow::Result<PathBuf> {
    if !is_managed_capture_file(file_name)
        || Path::new(file_name)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(file_name)
    {
        bail!("invalid managed pcap file name");
    }
    Ok(data_dir.join("pcap").join(file_name))
}

fn is_managed_capture_file(file_name: &str) -> bool {
    file_name
        .strip_prefix("pcap_")
        .and_then(|value| value.strip_suffix(".pcap"))
        .is_some_and(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{capture_file_name, cleanup_orphaned_capture_files, remove_capture_file};
    use std::collections::HashSet;

    #[tokio::test]
    async fn orphan_cleanup_only_removes_unreferenced_managed_files() {
        let data_dir = tempfile::tempdir().unwrap();
        let pcap_dir = data_dir.path().join("pcap");
        tokio::fs::create_dir_all(&pcap_dir).await.unwrap();
        tokio::fs::write(pcap_dir.join("pcap_instance-live.pcap"), b"live")
            .await
            .unwrap();
        tokio::fs::write(pcap_dir.join("pcap_instance-orphan.pcap"), b"orphan")
            .await
            .unwrap();
        tokio::fs::write(pcap_dir.join("notes.txt"), b"keep")
            .await
            .unwrap();
        tokio::fs::create_dir(pcap_dir.join("pcap_instance-directory.pcap"))
            .await
            .unwrap();
        let referenced = HashSet::from(["pcap_instance-live.pcap".to_string()]);

        let report = cleanup_orphaned_capture_files(data_dir.path(), &referenced)
            .await
            .unwrap();

        assert_eq!(report.removed, 1);
        assert!(report.failures.is_empty());
        assert!(pcap_dir.join("pcap_instance-live.pcap").exists());
        assert!(!pcap_dir.join("pcap_instance-orphan.pcap").exists());
        assert!(pcap_dir.join("notes.txt").exists());
        assert!(pcap_dir.join("pcap_instance-directory.pcap").exists());
    }

    #[tokio::test]
    async fn capture_file_removal_is_idempotent_and_rejects_unmanaged_paths() {
        let data_dir = tempfile::tempdir().unwrap();
        let pcap_dir = data_dir.path().join("pcap");
        tokio::fs::create_dir_all(&pcap_dir).await.unwrap();
        let file_name = capture_file_name("sim-019ff3b6-bb91-7f40-bee8-fb4689a0e599");
        tokio::fs::write(pcap_dir.join(&file_name), b"pcap")
            .await
            .unwrap();

        assert!(
            remove_capture_file(data_dir.path(), Some(&file_name))
                .await
                .unwrap()
        );
        assert!(
            !remove_capture_file(data_dir.path(), Some(&file_name))
                .await
                .unwrap()
        );
        assert!(
            remove_capture_file(data_dir.path(), Some("../escape.pcap"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn capture_file_removal_reports_filesystem_failures() {
        let data_dir = tempfile::tempdir().unwrap();
        let path = data_dir.path().join("pcap/pcap_instance-directory.pcap");
        tokio::fs::create_dir_all(&path).await.unwrap();

        let error = remove_capture_file(data_dir.path(), Some("pcap_instance-directory.pcap"))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("failed to remove pcap file"));
        assert!(path.exists());
    }
}
