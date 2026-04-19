//! # TgrCrypto Core
//!
//! High-performance Telegram cryptography library in Rust.
//!
//! Implements the AES-256 cipher modes required by Telegram's MTProto protocol:
//! - **IGE** (Infinite Garble Extension) — MTProto v2.0 message encryption
//! - **CTR** (Counter) — CDN encrypted file downloads
//! - **CBC** (Cipher Block Chaining) — Encrypted passport credentials
//!
//! Automatically uses AES-NI hardware acceleration on x86/x86_64 processors,
//! falling back to an optimized T-table software implementation on other platforms.
//!
//! # Security Notice
//!
//! The software T-table fallback is theoretically vulnerable to cache-timing
//! side-channel attacks (Bernstein 2005). On platforms without hardware AES
//! acceleration, evaluate this risk for your threat model. The `neon` feature
//! flag is reserved for future ARM NEON acceleration but is not yet implemented.

pub mod aes256;
pub mod cbc256;
pub mod ctr256;
pub mod ige256;

pub use aes256::ExpandedKey;
pub use cbc256::{cbc256_decrypt, cbc256_decrypt_into, cbc256_encrypt, cbc256_encrypt_into};
pub use ctr256::{ctr256_decrypt, ctr256_encrypt, ctr256_encrypt_into, ctr256_encrypt_into_ek};
/// Re-export the primary API functions for convenience.
pub use ige256::{
    ige256_decrypt, ige256_decrypt_into, ige256_decrypt_into_ek, ige256_encrypt,
    ige256_encrypt_into, ige256_encrypt_into_ek,
};
