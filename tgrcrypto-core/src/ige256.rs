//! AES-256-IGE (Infinite Garble Extension) mode.
//!
//! Used by Telegram MTProto v2.0 for message encryption.
//! Features zero-copy in-place memory projection.

use crate::aes256::{self, ExpandedKey, AES_BLOCK_SIZE};

/// Encrypt data in AES-256-IGE mode into a destination buffer.
pub fn ige256_encrypt_into(data: &[u8], key: &[u8; 32], iv: &mut [u8; 32], dest: &mut [u8]) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    if len == 0 || !len.is_multiple_of(AES_BLOCK_SIZE) {
        return;
    }

    let ek = ExpandedKey::new_encrypt(key);
    let mut iv1 = [0u8; AES_BLOCK_SIZE];
    let mut iv2 = [0u8; AES_BLOCK_SIZE];
    iv1.copy_from_slice(&iv[0..16]);
    iv2.copy_from_slice(&iv[16..32]);

    let mut i = 0;
    while i < len {
        let mut buffer = [0u8; AES_BLOCK_SIZE];
        for j in 0..AES_BLOCK_SIZE {
            buffer[j] = data[i + j] ^ iv1[j];
        }

        let mut encrypted = [0u8; AES_BLOCK_SIZE];
        aes256::encrypt_block(&buffer, &mut encrypted, &ek.words);

        for j in 0..AES_BLOCK_SIZE {
            dest[i + j] = encrypted[j] ^ iv2[j];
        }

        iv1.copy_from_slice(&dest[i..i + AES_BLOCK_SIZE]);
        iv2.copy_from_slice(&data[i..i + AES_BLOCK_SIZE]);

        i += AES_BLOCK_SIZE;
    }

    iv[0..16].copy_from_slice(&iv1);
    iv[16..32].copy_from_slice(&iv2);
}

/// Decrypt data in AES-256-IGE mode into a destination buffer.
pub fn ige256_decrypt_into(data: &[u8], key: &[u8; 32], iv: &mut [u8; 32], dest: &mut [u8]) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");
    if len == 0 || !len.is_multiple_of(AES_BLOCK_SIZE) {
        return;
    }

    let dk = ExpandedKey::new_decrypt(key);
    let mut iv1 = [0u8; AES_BLOCK_SIZE];
    let mut iv2 = [0u8; AES_BLOCK_SIZE];
    iv1.copy_from_slice(&iv[16..32]);
    iv2.copy_from_slice(&iv[0..16]);

    let mut i = 0;
    while i < len {
        let chunk = &data[i..i + AES_BLOCK_SIZE];

        let mut buffer = [0u8; AES_BLOCK_SIZE];
        for j in 0..AES_BLOCK_SIZE {
            buffer[j] = chunk[j] ^ iv1[j];
        }

        let mut decrypted = [0u8; AES_BLOCK_SIZE];
        aes256::decrypt_block(&buffer, &mut decrypted, &dk.words);

        for j in 0..AES_BLOCK_SIZE {
            dest[i + j] = decrypted[j] ^ iv2[j];
        }

        iv1.copy_from_slice(&dest[i..i + AES_BLOCK_SIZE]);
        iv2.copy_from_slice(chunk);

        i += AES_BLOCK_SIZE;
    }

    iv[0..16].copy_from_slice(&iv2);
    iv[16..32].copy_from_slice(&iv1);
}

/// Encrypt data in AES-256-IGE mode.
pub fn ige256_encrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut iv_clone = *iv;
    ige256_encrypt_into(data, key, &mut iv_clone, &mut out);
    out
}

/// Decrypt data in AES-256-IGE mode.
pub fn ige256_decrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut iv_clone = *iv;
    ige256_decrypt_into(data, key, &mut iv_clone, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ige_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 32];
        let data = vec![0xABu8; 64];

        let encrypted = ige256_encrypt(&data, &key, &iv);
        let decrypted = ige256_decrypt(&encrypted, &key, &iv);

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_ige_chunked_matches_one_shot() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 32];
        let data: Vec<u8> = (0..96).map(|i| (i & 0xff) as u8).collect();

        let one_shot = ige256_encrypt(&data, &key, &iv);

        let mut chunked_iv = iv;
        let mut chunked = Vec::with_capacity(data.len());
        for chunk in data.chunks(16) {
            let mut out = vec![0u8; chunk.len()];
            ige256_encrypt_into(chunk, &key, &mut chunked_iv, &mut out);
            chunked.extend(out);
        }

        assert_eq!(one_shot, chunked);
    }
}
