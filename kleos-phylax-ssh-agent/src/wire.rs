// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! SSH agent protocol wire format.
//!
//! Messages are u32-length-prefixed: `[length: u32 BE][type: u8][payload...]`.
//! Reference: draft-miller-ssh-agent (OpenSSH PROTOCOL.agent).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SSH agent message type constants.
pub mod msg {
    /// Agent failure response.
    pub const SSH_AGENT_FAILURE: u8 = 5;
    /// Agent success response.
    pub const SSH_AGENT_SUCCESS: u8 = 6;
    /// Request: list identities.
    pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    /// Response: identities list.
    pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    /// Request: sign data.
    pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    /// Response: signature.
    pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    /// Request: add identity (rejected by Phylax).
    pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
    /// Request: remove identity (rejected by Phylax).
    pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
    /// Request: remove all identities (rejected by Phylax).
    pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
    /// Request: lock agent.
    pub const SSH_AGENTC_LOCK: u8 = 22;
    /// Request: unlock agent (rejected by Phylax).
    pub const SSH_AGENTC_UNLOCK: u8 = 23;
}

/// Maximum message size (10 MB, matching OpenSSH).
const MAX_MSG_LEN: u32 = 10 * 1024 * 1024;

/// A raw SSH agent message (type byte + payload).
#[derive(Debug)]
pub struct AgentMessage {
    /// Message type byte.
    pub msg_type: u8,
    /// Payload bytes (everything after the type byte).
    pub payload: Vec<u8>,
}

/// Reads one SSH agent message from the stream.
///
/// Returns `None` on EOF (clean disconnect).
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<AgentMessage>> {
    let len = match reader.read_u32().await {
        Ok(len) => len,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };

    if len == 0 || len > MAX_MSG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid message length: {len}"),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    let msg_type = buf[0];
    let payload = buf[1..].to_vec();

    Ok(Some(AgentMessage { msg_type, payload }))
}

/// Writes one SSH agent message to the stream.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = (1 + payload.len()) as u32;
    writer.write_u32(len).await?;
    writer.write_u8(msg_type).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Writes a simple SSH_AGENT_FAILURE response.
pub async fn write_failure<W: AsyncWrite + Unpin>(writer: &mut W) -> std::io::Result<()> {
    write_message(writer, msg::SSH_AGENT_FAILURE, &[]).await
}

/// Writes a simple SSH_AGENT_SUCCESS response.
pub async fn write_success<W: AsyncWrite + Unpin>(writer: &mut W) -> std::io::Result<()> {
    write_message(writer, msg::SSH_AGENT_SUCCESS, &[]).await
}

/// Writes a u32 in big-endian to a buffer.
pub fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Writes a length-prefixed byte string to a buffer.
pub fn push_string(buf: &mut Vec<u8>, data: &[u8]) {
    push_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

/// Reads a u32 from a byte slice at the given offset, advancing the offset.
pub fn read_u32(data: &[u8], offset: &mut usize) -> std::io::Result<u32> {
    if *offset + 4 > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated u32",
        ));
    }
    let val = u32::from_be_bytes(data[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(val)
}

/// Reads a length-prefixed byte string from a byte slice at the given offset.
pub fn read_string<'a>(data: &'a [u8], offset: &mut usize) -> std::io::Result<&'a [u8]> {
    let len = read_u32(data, offset)? as usize;
    if *offset + len > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated string",
        ));
    }
    let result = &data[*offset..*offset + len];
    *offset += len;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_message() {
        let mut buf = Vec::new();
        write_message(&mut buf, msg::SSH_AGENTC_REQUEST_IDENTITIES, &[])
            .await
            .unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let msg = read_message(&mut cursor).await.unwrap().unwrap();
        assert_eq!(msg.msg_type, msg::SSH_AGENTC_REQUEST_IDENTITIES);
        assert!(msg.payload.is_empty());
    }

    #[tokio::test]
    async fn round_trip_with_payload() {
        let payload = b"test data";
        let mut buf = Vec::new();
        write_message(&mut buf, msg::SSH_AGENTC_SIGN_REQUEST, payload)
            .await
            .unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let msg = read_message(&mut cursor).await.unwrap().unwrap();
        assert_eq!(msg.msg_type, msg::SSH_AGENTC_SIGN_REQUEST);
        assert_eq!(msg.payload, payload);
    }

    #[tokio::test]
    async fn eof_returns_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let msg = read_message(&mut cursor).await.unwrap();
        assert!(msg.is_none());
    }

    #[test]
    fn push_and_read_string() {
        let mut buf = Vec::new();
        push_string(&mut buf, b"hello");

        let mut offset = 0;
        let result = read_string(&buf, &mut offset).unwrap();
        assert_eq!(result, b"hello");
        assert_eq!(offset, 9); // 4 byte len + 5 bytes
    }
}
