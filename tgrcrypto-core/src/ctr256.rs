//! AES-256-CTR (Counter) mode.
//!
//! Used by Telegram for CDN encrypted file downloads.
//! Features stateful streaming support, SIMD batching, and Rayon multithreading.

use crate::aes256::{self, ExpandedKey, AES_BLOCK_SIZE};
use rayon::prelude::*;

const PARALLEL_THRESHOLD: usize = 256 * 1024; // 256 KB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB per thread

/// Increment a 16-byte big-endian counter by 1.
#[inline]
fn increment_counter(iv: &mut [u8; 16]) {
    let mut k = AES_BLOCK_SIZE;
    while k > 0 {
        k -= 1;
        iv[k] = iv[k].wrapping_add(1);
        if iv[k] != 0 {
            break;
        }
    }
}

/// Add a 64-bit value to a 16-byte big-endian counter.
#[inline]
fn add_counter(iv: &[u8; 16], offset: u64) -> [u8; 16] {
    let mut out = *iv;
    let mut carry = offset;
    let mut k = AES_BLOCK_SIZE;
    while k > 0 && carry > 0 {
        k -= 1;
        let sum = (out[k] as u64) + (carry & 0xFF);
        out[k] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    // If carry is still > 0, it means the 64-bit addition overflowed into the top 8 bytes.
    while k > 0 && carry > 0 {
        k -= 1;
        let sum = (out[k] as u64) + (carry & 0xFF);
        out[k] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    out
}

/// Encrypt/decrypt data in AES-256-CTR into a destination buffer.
pub fn ctr256_encrypt_into(
    data: &[u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut u8,
    dest: &mut [u8],
) {
    let len = data.len();
    assert_eq!(len, dest.len(), "Source and destination lengths must match");

    if len == 0 {
        return;
    }

    let ek = ExpandedKey::new_encrypt(key);

    if len < PARALLEL_THRESHOLD {
        ctr256_encrypt_internal(data, dest, &ek, iv, state);
        return;
    }

    let mut processed = 0;
    if *state != 0 {
        let mut chunk = [0u8; 16];
        aes256::encrypt_block(iv, &mut chunk, &ek.words);
        let rem = AES_BLOCK_SIZE - (*state as usize);
        let advance = core::cmp::min(len, rem);

        for pos in 0..advance {
            dest[pos] = data[pos] ^ chunk[*state as usize + pos];
        }

        *state += advance as u8;
        if *state >= AES_BLOCK_SIZE as u8 {
            *state = 0;
            increment_counter(iv);
        }
        processed += advance;
    }

    if processed == len {
        return;
    }

    let rem_data = &data[processed..];
    let rem_dest = &mut dest[processed..];
    let bulk_len = (rem_data.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    if bulk_len > 0 {
        let bulk_data = &rem_data[..bulk_len];
        let bulk_dest = &mut rem_dest[..bulk_len];

        bulk_data
            .par_chunks(CHUNK_SIZE)
            .zip(bulk_dest.par_chunks_mut(CHUNK_SIZE))
            .enumerate()
            .for_each(|(chunk_idx, (chunk_data, chunk_dest))| {
                let block_offset = (chunk_idx * CHUNK_SIZE / AES_BLOCK_SIZE) as u64;
                let mut local_iv = add_counter(iv, block_offset);
                let mut local_state = 0u8;
                ctr256_encrypt_internal(
                    chunk_data,
                    chunk_dest,
                    &ek,
                    &mut local_iv,
                    &mut local_state,
                );
            });

        let blocks_processed = (bulk_len / AES_BLOCK_SIZE) as u64;
        *iv = add_counter(iv, blocks_processed);
        processed += bulk_len;
    }

    if processed < len {
        let tail_data = &data[processed..];
        let tail_dest = &mut dest[processed..];
        ctr256_encrypt_internal(tail_data, tail_dest, &ek, iv, state);
    }
}

/// Internal sequential CTR processor with 4-way SIMD batched acceleration.
fn ctr256_encrypt_internal(
    data: &[u8],
    dest: &mut [u8],
    ek: &ExpandedKey,
    iv: &mut [u8; 16],
    state: &mut u8,
) {
    let mut i = 0;
    let len = data.len();

    if *state > 0 {
        let mut chunk = [0u8; 16];
        aes256::encrypt_block(iv, &mut chunk, &ek.words);

        while i < len && *state > 0 {
            dest[i] = data[i] ^ chunk[*state as usize];
            *state = (*state + 1) % 16;
            i += 1;
            if *state == 0 {
                increment_counter(iv);
                break;
            }
        }
    }

    // 4-block SIMD interleaved path
    while i + 64 <= len {
        let mut ivs = [0u8; 64];

        ivs[0..16].copy_from_slice(iv);
        increment_counter(iv);
        ivs[16..32].copy_from_slice(iv);
        increment_counter(iv);
        ivs[32..48].copy_from_slice(iv);
        increment_counter(iv);
        ivs[48..64].copy_from_slice(iv);
        increment_counter(iv);

        let mut keystream = [0u8; 64];
        aes256::encrypt_block_x4(&ivs, &mut keystream, &ek.words);

        for j in 0..64 {
            dest[i + j] = data[i + j] ^ keystream[j];
        }
        i += 64;
    }

    while i + 16 <= len {
        let mut keystream = [0u8; 16];
        aes256::encrypt_block(iv, &mut keystream, &ek.words);
        increment_counter(iv);

        for j in 0..16 {
            dest[i + j] = data[i + j] ^ keystream[j];
        }
        i += 16;
    }

    if i < len {
        let mut keystream = [0u8; 16];
        aes256::encrypt_block(iv, &mut keystream, &ek.words);

        while i < len {
            dest[i] = data[i] ^ keystream[*state as usize];
            *state += 1;
            i += 1;
        }
    }
}

pub fn ctr256_encrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], state: &mut u8) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    ctr256_encrypt_into(data, key, iv, state, &mut out);
    out
}

#[inline]
pub fn ctr256_decrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], state: &mut u8) -> Vec<u8> {
    ctr256_encrypt(data, key, iv, state)
}
