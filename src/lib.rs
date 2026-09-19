//! YOLO-Shell: a gatekeeper between a typed command and its execution.
//!
//! `fastpath` clears the obviously safe. `jev_client` rules on the rest,
//! falling back to `heuristics` when the network can't answer in time.
//! `redact` scrubs the payload on its way out. `daemon` optionally holds the
//! Jev connection open so each command skips the TLS handshake.
//!
//! Every stage fails open. Locking someone out of their own terminal is a
//! worse bug than the one we're preventing.

pub mod daemon;
pub mod fastpath;
pub mod heuristics;
pub mod jev_client;
pub mod redact;
