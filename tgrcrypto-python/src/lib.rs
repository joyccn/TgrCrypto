//! Python bindings for TgrCrypto.
//!
//! Provides a drop-in replacement for TgCrypto with identical API:
//! - `ige256_encrypt(data, key, iv) -> bytes`
//! - `ige256_decrypt(data, key, iv) -> bytes`
//! - `ctr256_encrypt(data, key, iv, state) -> bytes`
//! - `ctr256_decrypt(data, key, iv, state) -> bytes`
//! - `cbc256_encrypt(data, key, iv) -> bytes`
//! - `cbc256_decrypt(data, key, iv) -> bytes`
//! - `Ctr256` - Stateful CTR stream cipher class
//! - `Ige256` - Stateful IGE stream cipher class
//!
//! Supports Python 3.9–3.14.

use core::slice;
use pyo3::exceptions::{PyMemoryError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Create a Python ValueError with a formatted message.
fn value_error(msg: impl Into<String>) -> PyErr {
    PyValueError::new_err(msg.into())
}

/// Zero-copy PyBytes allocation with GIL release.
///
/// Allocates uninitialized Python bytes, releases the GIL,
/// runs the cipher operation in-place, and returns the result.
fn execute_zerocopy<'py, F>(py: Python<'py>, data: &[u8], f: F) -> PyResult<Bound<'py, PyBytes>>
where
    F: FnOnce(&mut [u8]) + Send,
{
    let len = data.len();

    let obj_ptr = unsafe { ffi::PyBytes_FromStringAndSize(std::ptr::null(), len as isize) };
    if obj_ptr.is_null() {
        return Err(PyMemoryError::new_err(
            "Failed to allocate memory for ciphertext/plaintext",
        ));
    }

    let dest_ptr = unsafe { ffi::PyBytes_AsString(obj_ptr) } as usize;

    py.detach(move || {
        // SAFETY: dest_ptr is valid for `len` bytes and exclusively owned.
        let dest = unsafe { slice::from_raw_parts_mut(dest_ptr as *mut u8, len) };
        f(dest);
    });

    unsafe {
        let any = Bound::from_owned_ptr(py, obj_ptr);
        let bytes: Bound<'py, PyBytes> = any.cast_into_unchecked();
        Ok(bytes)
    }
}

/// AES-256-IGE encryption.
///
/// Encrypts data using AES-256 in Infinite Garble Extension (IGE) mode.
/// This mode is used by Telegram MTProto v2.0 for message encryption.
///
/// # Arguments
/// * `data` - Plaintext to encrypt (must be multiple of 16 bytes)
/// * `key` - 32-byte encryption key
/// * `iv` - 32-byte initial value
///
/// # Returns
/// Encrypted ciphertext as bytes
///
/// # Raises
/// * `ValueError` - If data is empty, not a multiple of 16 bytes, or key/IV sizes are incorrect
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(value_error("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(value_error(format!(
            "Data size must be a multiple of 16 bytes, got {} bytes",
            data.len()
        )));
    }
    if key.len() != 32 {
        return Err(value_error(format!(
            "Key size must be exactly 32 bytes, got {} bytes",
            key.len()
        )));
    }
    if iv.len() != 32 {
        return Err(value_error(format!(
            "IV size must be exactly 32 bytes, got {} bytes",
            iv.len()
        )));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 32] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::ige256_encrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// AES-256-IGE decryption.
///
/// Decrypts data using AES-256 in Infinite Garble Extension (IGE) mode.
///
/// # Arguments
/// * `data` - Ciphertext to decrypt (must be multiple of 16 bytes)
/// * `key` - 32-byte decryption key
/// * `iv` - 32-byte initial value (same as used for encryption)
///
/// # Returns
/// Decrypted plaintext as bytes
///
/// # Raises
/// * `ValueError` - If data is empty, not a multiple of 16 bytes, or key/IV sizes are incorrect
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(value_error("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(value_error(format!(
            "Data size must be a multiple of 16 bytes, got {} bytes",
            data.len()
        )));
    }
    if key.len() != 32 {
        return Err(value_error(format!(
            "Key size must be exactly 32 bytes, got {} bytes",
            key.len()
        )));
    }
    if iv.len() != 32 {
        return Err(value_error(format!(
            "IV size must be exactly 32 bytes, got {} bytes",
            iv.len()
        )));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 32] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::ige256_decrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// AES-256-CTR encryption.
///
/// Encrypts data using AES-256 in Counter (CTR) mode.
/// This mode supports arbitrary length data and is used for CDN encrypted file downloads.
///
/// # Arguments
/// * `data` - Plaintext to encrypt (arbitrary length)
/// * `key` - 32-byte encryption key
/// * `iv` - 16-byte initial counter value
/// * `state` - 1-byte counter state (0-15), usually starts at 0
///
/// # Returns
/// Encrypted ciphertext as bytes
///
/// # Raises
/// * `ValueError` - If data is empty, or key/IV/state sizes are incorrect
#[pyfunction]
#[pyo3(signature = (data, key, iv, state))]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    state: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(value_error("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(value_error(format!(
            "Key size must be exactly 32 bytes, got {} bytes",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(value_error(format!(
            "IV size must be exactly 16 bytes, got {} bytes",
            iv.len()
        )));
    }
    if state.len() != 1 {
        return Err(value_error(format!(
            "State size must be exactly 1 byte, got {} bytes",
            state.len()
        )));
    }
    if state[0] > 15 {
        return Err(value_error(format!(
            "State value must be in the range [0, 15], got {}",
            state[0]
        )));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 16] = iv.try_into().unwrap();
    let mut state_val = state[0];

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::ctr256_encrypt_into(data, key_arr, &mut iv_arr, &mut state_val, dest);
    })
}

/// AES-256-CTR decryption (symmetric with encrypt).
///
/// Decrypts data using AES-256 in Counter (CTR) mode.
/// CTR mode is symmetric - encryption and decryption use the same operation.
///
/// # Arguments
/// * `data` - Ciphertext to decrypt (arbitrary length)
/// * `key` - 32-byte decryption key
/// * `iv` - 16-byte initial counter value
/// * `state` - 1-byte counter state (0-15), usually starts at 0
///
/// # Returns
/// Decrypted plaintext as bytes
///
/// # Raises
/// * `ValueError` - If data is empty, or key/IV/state sizes are incorrect
#[pyfunction]
#[pyo3(signature = (data, key, iv, state))]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
    state: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, data, key, iv, state)
}

/// AES-256-CBC encryption.
///
/// Encrypts data using AES-256 in Cipher Block Chaining (CBC) mode.
/// This mode is used for encrypted passport credentials in Telegram.
///
/// # Arguments
/// * `data` - Plaintext to encrypt (must be multiple of 16 bytes)
/// * `key` - 32-byte encryption key
/// * `iv` - 16-byte initial value
///
/// # Returns
/// Encrypted ciphertext as bytes
///
/// # Raises
/// * `ValueError` - If data is empty, not a multiple of 16 bytes, or key/IV sizes are incorrect
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(value_error("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(value_error(format!(
            "Data size must be a multiple of 16 bytes, got {} bytes",
            data.len()
        )));
    }
    if key.len() != 32 {
        return Err(value_error(format!(
            "Key size must be exactly 32 bytes, got {} bytes",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(value_error(format!(
            "IV size must be exactly 16 bytes, got {} bytes",
            iv.len()
        )));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 16] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::cbc256_encrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// AES-256-CBC decryption.
///
/// Decrypts data using AES-256 in Cipher Block Chaining (CBC) mode.
///
/// # Arguments
/// * `data` - Ciphertext to decrypt (must be multiple of 16 bytes)
/// * `key` - 32-byte decryption key
/// * `iv` - 16-byte initial value (same as used for encryption)
///
/// # Returns
/// Decrypted plaintext as bytes
///
/// # Raises
/// * `ValueError` - If data is empty, not a multiple of 16 bytes, or key/IV sizes are incorrect
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn cbc256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(value_error("Data must not be empty"));
    }
    if data.len() % 16 != 0 {
        return Err(value_error(format!(
            "Data size must be a multiple of 16 bytes, got {} bytes",
            data.len()
        )));
    }
    if key.len() != 32 {
        return Err(value_error(format!(
            "Key size must be exactly 32 bytes, got {} bytes",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(value_error(format!(
            "IV size must be exactly 16 bytes, got {} bytes",
            iv.len()
        )));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 16] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::cbc256_decrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// Stateful AES-256-CTR stream cipher.
///
/// This class maintains internal state across multiple `update()` calls,
/// allowing incremental encryption/decryption of data streams.
///
/// Example:
///     >>> key = os.urandom(32)
///     >>> iv = os.urandom(16)
///     >>> stream = tgcrypto.Ctr256(key, iv)
///     >>> chunk1 = stream.update(data[:512])
///     >>> chunk2 = stream.update(data[512:])
#[pyclass]
struct Ctr256 {
    key: [u8; 32],
    iv: [u8; 16],
    state: u8,
}

#[pymethods]
impl Ctr256 {
    /// Create a new CTR-256 stream cipher.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `iv` - 16-byte initial counter value
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| value_error("Key must be exactly 32 bytes"))?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| value_error("IV must be exactly 16 bytes"))?;
        Ok(Ctr256 {
            key: key_arr,
            iv: iv_arr,
            state: 0,
        })
    }

    /// Encrypt/decrypt a chunk of data, updating internal state.
    ///
    /// # Arguments
    /// * `data` - Data to process (arbitrary length)
    fn update<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let key_arr = self.key;
        let mut iv_arr = self.iv;
        let mut state_val = self.state;

        let res = execute_zerocopy(py, data, move |dest| {
            tgrcrypto_core::ctr256_encrypt_into(data, &key_arr, &mut iv_arr, &mut state_val, dest);
        })?;

        self.iv = iv_arr;
        self.state = state_val;
        Ok(res)
    }
}

/// Stateful AES-256-IGE stream cipher.
///
/// This class maintains IV state across multiple `encrypt()`/`decrypt()` calls,
/// allowing incremental processing of data in IGE mode.
///
/// Note: IGE mode requires data to be a multiple of 16 bytes.
///
/// Example:
///     >>> key = os.urandom(32)
///     >>> iv = os.urandom(32)
///     >>> stream = tgcrypto.Ige256(key, iv)
///     >>> chunk1 = stream.encrypt(data[:1024])
///     >>> chunk2 = stream.encrypt(data[1024:])
#[pyclass]
struct Ige256 {
    key: [u8; 32],
    iv: [u8; 32],
}

#[pymethods]
impl Ige256 {
    /// Create a new IGE-256 stream cipher.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `iv` - 32-byte initial value (two 16-byte IVs concatenated)
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| value_error("Key must be exactly 32 bytes"))?;
        let iv_arr: [u8; 32] = iv
            .try_into()
            .map_err(|_| value_error("IV must be exactly 32 bytes"))?;
        Ok(Ige256 {
            key: key_arr,
            iv: iv_arr,
        })
    }

    /// Encrypt a chunk of data, updating IV state.
    ///
    /// # Arguments
    /// * `data` - Data to encrypt (must be multiple of 16 bytes)
    fn encrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if data.len() % 16 != 0 {
            return Err(value_error(format!(
                "Data size must be a multiple of 16 bytes, got {} bytes",
                data.len()
            )));
        }
        let key_arr = self.key;
        let mut iv_arr = self.iv;

        let res = execute_zerocopy(py, data, move |dest| {
            tgrcrypto_core::ige256_encrypt_into(data, &key_arr, &mut iv_arr, dest);
        })?;

        self.iv = iv_arr;
        Ok(res)
    }

    /// Decrypt a chunk of data, updating IV state.
    ///
    /// # Arguments
    /// * `data` - Data to decrypt (must be multiple of 16 bytes)
    fn decrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if data.len() % 16 != 0 {
            return Err(value_error(format!(
                "Data size must be a multiple of 16 bytes, got {} bytes",
                data.len()
            )));
        }
        let key_arr = self.key;
        let mut iv_arr = self.iv;

        let res = execute_zerocopy(py, data, move |dest| {
            tgrcrypto_core::ige256_decrypt_into(data, &key_arr, &mut iv_arr, dest);
        })?;

        self.iv = iv_arr;
        Ok(res)
    }
}

/// TgrCrypto Python module.
///
/// High-performance, AES-NI accelerated drop-in replacement for TgCrypto.
///
/// This module provides three cipher modes:
/// - **IGE-256**: Used by Telegram MTProto v2.0 for message encryption
/// - **CTR-256**: Used for CDN encrypted file downloads (supports arbitrary length data)
/// - **CBC-256**: Used for encrypted passport credentials
///
/// All functions operate on bytes-like objects and return bytes.
/// The library automatically uses AES-NI hardware acceleration when available.
///
/// Example:
///     >>> import tgcrypto
///     >>> import os
///     >>> data = os.urandom(1024)
///     >>> key = os.urandom(32)
///     >>> iv = os.urandom(32)
///     >>> encrypted = tgcrypto.ige256_encrypt(data, key, iv)
///     >>> decrypted = tgcrypto.ige256_decrypt(encrypted, key, iv)
///     >>> decrypted == data
///     True
#[pymodule]
fn tgcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_decrypt, m)?)?;

    m.add_class::<Ctr256>()?;
    m.add_class::<Ige256>()?;

    Ok(())
}
