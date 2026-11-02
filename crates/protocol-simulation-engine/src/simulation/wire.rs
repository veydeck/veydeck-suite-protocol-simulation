//! Bounded wire framing shared by the discovery-only protocol handlers.
use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Duration, timeout};

pub const MAX_FRAME: usize = 64 * 1024;
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let bytes = (value.len() as u32).to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(3);
        out.push(0x80 | (4 - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(value);
    out
}

pub fn take_tlv<'a>(input: &mut &'a [u8]) -> anyhow::Result<(u8, &'a [u8])> {
    if input.len() < 2 {
        bail!("truncated BER header");
    }
    let tag = input[0];
    let first = input[1];
    let count = if first & 0x80 == 0 {
        0
    } else {
        usize::from(first & 0x7f)
    };
    if first == 0x80 || count > 4 || input.len() < 2 + count {
        bail!("invalid BER length");
    }
    let length = if count == 0 {
        usize::from(first)
    } else {
        input[2..2 + count]
            .iter()
            .fold(0_usize, |n, b| (n << 8) | usize::from(*b))
    };
    if length > MAX_FRAME || input.len() < 2 + count + length {
        bail!("invalid BER value length");
    }
    let value = &input[2 + count..2 + count + length];
    *input = &input[2 + count + length..];
    Ok((tag, value))
}

pub async fn read_ber<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>> {
    timeout(IDLE_TIMEOUT, async {
        let tag = match reader.read_u8().await {
            Ok(tag) => tag,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        anyhow::ensure!(tag == 0x30, "expected BER sequence envelope");
        let first = reader.read_u8().await?;
        let mut header = vec![tag, first];
        let count = if first & 0x80 == 0 {
            0
        } else {
            usize::from(first & 0x7f)
        };
        if first == 0x80 || count > 4 {
            bail!("invalid BER length");
        }
        let length = if count == 0 {
            usize::from(first)
        } else {
            let mut bytes = vec![0; count];
            reader.read_exact(&mut bytes).await?;
            header.extend_from_slice(&bytes);
            bytes
                .iter()
                .fold(0_usize, |n, b| (n << 8) | usize::from(*b))
        };
        if length > MAX_FRAME {
            bail!("BER frame exceeds limit");
        }
        header.resize(header.len() + length, 0);
        reader.read_exact(&mut header[2 + count..]).await?;
        Ok(Some(header))
    })
    .await
    .context("BER read timed out")?
}

pub async fn read_netbios<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>> {
    timeout(IDLE_TIMEOUT, async {
        let first = match reader.read_u8().await {
            Ok(byte) => byte,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if first != 0 {
            bail!("unsupported NetBIOS message type");
        }
        let mut length = [0; 3];
        reader.read_exact(&mut length).await?;
        let size =
            (usize::from(length[0]) << 16) | (usize::from(length[1]) << 8) | usize::from(length[2]);
        if !(32..=MAX_FRAME).contains(&size) {
            bail!("invalid SMB frame length");
        }
        let mut payload = vec![0; size];
        reader.read_exact(&mut payload).await?;
        Ok(Some(payload))
    })
    .await
    .context("SMB read timed out")?
}

/// Bounded line reading avoids unbounded allocation on a peer that never sends LF.
pub async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<String>> {
    use tokio::io::AsyncBufReadExt;
    timeout(IDLE_TIMEOUT, async {
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if line.is_empty() {
                    return Ok(None);
                }
                bail!("truncated line");
            }
            let end = available.iter().position(|b| *b == b'\n').map(|i| i + 1);
            let length = end.unwrap_or(available.len());
            if line.len() + length > 8192 {
                bail!("line exceeds 8192 bytes");
            }
            line.extend_from_slice(&available[..length]);
            reader.consume(length);
            if end.is_some() {
                return Ok(Some(
                    String::from_utf8(line)?
                        .trim_end_matches(['\r', '\n'])
                        .to_string(),
                ));
            }
        }
    })
    .await
    .context("line read timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn ber_handles_fragmentation_and_consecutive_messages() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let frame = tlv(0x30, &[42; 130]);
        let expected = frame.clone();
        let task = tokio::spawn(async move {
            for byte in frame.iter().chain(frame.iter()) {
                writer.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        assert_eq!(read_ber(&mut reader).await.unwrap().unwrap(), expected);
        assert_eq!(read_ber(&mut reader).await.unwrap().unwrap(), expected);
        assert!(read_ber(&mut reader).await.unwrap().is_none());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_indefinite_oversized_and_truncated_frames() {
        for data in [
            &b"\x30\x80"[..],
            &b"\x30\x83\x01\x00\x01"[..],
            &b"\x30\x02\x00"[..],
        ] {
            assert!(read_ber(&mut &data[..]).await.is_err());
        }
        assert!(read_netbios(&mut &b"\0\x01\0\x01"[..]).await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn idle_and_partial_frames_time_out() {
        let (_writer, mut reader) = tokio::io::duplex(32);
        assert!(
            read_ber(&mut reader)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(
            read_netbios(&mut reader)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(
            read_line(&mut reader)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
    }
    #[tokio::test]
    async fn lines_are_bounded_and_preserve_consecutive_requests() {
        let mut data = &b"first\r\nsecond\r\n"[..];
        assert_eq!(read_line(&mut data).await.unwrap().unwrap(), "first");
        assert_eq!(read_line(&mut data).await.unwrap().unwrap(), "second");
        assert!(read_line(&mut data).await.unwrap().is_none());
        assert!(read_line(&mut &vec![b'x'; 8193][..]).await.is_err());
        assert!(read_line(&mut &b"incomplete"[..]).await.is_err());
    }
}
