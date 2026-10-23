// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! OpenSSH agent protocol server for Phylax.
//!
//! This crate implements the SSH agent wire protocol and delegates key
//! operations through a [`KeyProvider`] trait. The transport layer is
//! generic over `AsyncRead + AsyncWrite`, so it works with both Unix
//! sockets and Windows named pipes.
//!
//! # Usage
//!
//! 1. Implement [`KeyProvider`] to bridge your key storage.
//! 2. Create an [`AgentServer`] with a socket/pipe path and provider.
//! 3. Call [`AgentServer::run`] with a cancellation token.

pub mod handler;
pub mod provider;
pub mod server;
pub mod wire;

pub use provider::{AgentIdentity, KeyProvider, SignError};
pub use server::AgentServer;
