// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! SSH agent message handler.
//!
//! Dispatches incoming protocol messages to the appropriate KeyProvider
//! methods and constructs response messages.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::provider::KeyProvider;
use crate::wire::{self, msg, read_message, write_failure, write_message};

/// Handles one SSH agent connection (one stream of messages).
///
/// Reads messages in a loop until EOF or error, dispatching each to
/// the appropriate handler.
pub async fn handle_connection<S, P>(mut stream: S, provider: &P)
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: KeyProvider,
{
    loop {
        let message = match read_message(&mut stream).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break, // Clean EOF.
            Err(e) => {
                log::debug!("SSH agent read error: {e}");
                break;
            }
        };

        let result = match message.msg_type {
            msg::SSH_AGENTC_REQUEST_IDENTITIES => handle_identities(&mut stream, provider).await,
            msg::SSH_AGENTC_SIGN_REQUEST => {
                handle_sign(&mut stream, &message.payload, provider).await
            }
            msg::SSH_AGENTC_ADD_IDENTITY
            | msg::SSH_AGENTC_REMOVE_IDENTITY
            | msg::SSH_AGENTC_REMOVE_ALL_IDENTITIES
            | msg::SSH_AGENTC_LOCK
            | msg::SSH_AGENTC_UNLOCK => {
                // Rejected: keys are managed through the Phylax UI. LOCK is
                // rejected too -- this agent has no UNLOCK path (above), so
                // honoring LOCK (which cleared the identity cache) permanently
                // bricked the agent until restart. Fail cleanly instead.
                write_failure(&mut stream).await
            }
            _ => {
                log::debug!("Unknown SSH agent message type: {}", message.msg_type);
                write_failure(&mut stream).await
            }
        };

        if let Err(e) = result {
            log::debug!("SSH agent write error: {e}");
            break;
        }
    }
}

/// Handles SSH_AGENTC_REQUEST_IDENTITIES: returns loaded key list.
async fn handle_identities<S, P>(stream: &mut S, provider: &P) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    P: KeyProvider,
{
    let identities = provider.identities();

    let mut payload = Vec::new();
    wire::push_u32(&mut payload, identities.len() as u32);

    for id in &identities {
        let key_blob = id
            .public_key
            .to_bytes()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        wire::push_string(&mut payload, &key_blob);
        wire::push_string(&mut payload, id.comment.as_bytes());
    }

    write_message(stream, msg::SSH_AGENT_IDENTITIES_ANSWER, &payload).await
}

/// Handles SSH_AGENTC_SIGN_REQUEST: signs data with the requested key.
async fn handle_sign<S, P>(stream: &mut S, payload: &[u8], provider: &P) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    P: KeyProvider,
{
    let mut offset = 0;

    // Parse key blob.
    let key_blob = match wire::read_string(payload, &mut offset) {
        Ok(b) => b,
        Err(_) => return write_failure(stream).await,
    };

    // Parse data to sign.
    let data = match wire::read_string(payload, &mut offset) {
        Ok(d) => d,
        Err(_) => return write_failure(stream).await,
    };

    // Parse flags.
    // Flags are optional in some implementations.
    let flags = wire::read_u32(payload, &mut offset).unwrap_or_default();

    // Delegate to the provider.
    match provider.sign(key_blob, data, flags).await {
        Ok(signature) => {
            let mut response = Vec::new();
            wire::push_string(&mut response, &signature);
            write_message(stream, msg::SSH_AGENT_SIGN_RESPONSE, &response).await
        }
        Err(e) => {
            log::debug!("Sign request failed: {e}");
            write_failure(stream).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{AgentIdentity, SignError};

    /// Mock provider that returns a fixed set of identities and signs with a test key.
    struct MockProvider {
        identities: Vec<AgentIdentity>,
    }

    impl KeyProvider for MockProvider {
        fn identities(&self) -> Vec<AgentIdentity> {
            self.identities.clone()
        }

        async fn sign(
            &self,
            _key_blob: &[u8],
            _data: &[u8],
            _flags: u32,
        ) -> Result<Vec<u8>, SignError> {
            // Return a dummy signature.
            Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
        }

        async fn on_lock(&self) {}
    }

    #[tokio::test]
    async fn request_identities_empty() {
        let provider = MockProvider { identities: vec![] };

        // Build request.
        let mut request = Vec::new();
        wire::write_message(&mut request, msg::SSH_AGENTC_REQUEST_IDENTITIES, &[])
            .await
            .unwrap();

        // Handle.
        let stream = tokio::io::duplex(4096);
        let (mut client_read, mut server_write) = (stream.0, stream.1);

        // Write request, handle, read response in separate tasks.
        let mut combined = std::io::Cursor::new(request);
        let msg = read_message(&mut combined).await.unwrap().unwrap();
        assert_eq!(msg.msg_type, msg::SSH_AGENTC_REQUEST_IDENTITIES);

        handle_identities(&mut server_write, &provider)
            .await
            .unwrap();
        drop(server_write); // Signal EOF.

        let response = read_message(&mut client_read).await.unwrap().unwrap();
        assert_eq!(response.msg_type, msg::SSH_AGENT_IDENTITIES_ANSWER);

        // Parse nkeys = 0.
        let mut offset = 0;
        let nkeys = wire::read_u32(&response.payload, &mut offset).unwrap();
        assert_eq!(nkeys, 0);
    }

    #[tokio::test]
    async fn reject_add_identity() {
        let provider = MockProvider { identities: vec![] };

        let (mut client, server) = tokio::io::duplex(4096);

        // Send ADD_IDENTITY.
        wire::write_message(&mut client, msg::SSH_AGENTC_ADD_IDENTITY, &[])
            .await
            .unwrap();
        drop(client);

        handle_connection(server, &provider).await;
    }
}
