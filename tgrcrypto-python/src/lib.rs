//! Python bindings for TgrCrypto.
//!
//! Provides a drop-in replacement for TgCrypto with identical API:
//! - `ige256_encrypt(data, key, iv) -> bytes`
//! - `ige256_decrypt(data, key, iv) -> bytes`
//! - `ctr256_encrypt(data, key, iv, state) -> bytes`
//! - `ctr256_decrypt(data, key, iv, state) -> bytes`
//! - `cbc256_encrypt(data, key, iv) -> bytes`
//! - `cbc256_decrypt(data, key, iv) -> bytes`

use core::slice;
use pyo3::exceptions::{PyMemoryError, PyValueError};
use pyo3::ffi;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

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
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if !data.len().is_multiple_of(16) {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyValueError::new_err("IV size must be exactly 32 bytes"));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 32] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::ige256_encrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// AES-256-IGE decryption.
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if !data.len().is_multiple_of(16) {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyValueError::new_err("IV size must be exactly 32 bytes"));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 32] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::ige256_decrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// AES-256-CTR encryption.
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
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    if state.len() != 1 {
        return Err(PyValueError::new_err("State size must be exactly 1 byte"));
    }
    if state[0] > 15 {
        return Err(PyValueError::new_err(
            "State value must be in the range [0, 15]",
        ));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 16] = iv.try_into().unwrap();
    let mut state_val = state[0];

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::ctr256_encrypt_into(data, key_arr, &mut iv_arr, &mut state_val, dest);
    })
}

/// AES-256-CTR decryption (symmetric with encrypt).
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
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if !data.len().is_multiple_of(16) {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 16] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::cbc256_encrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// AES-256-CBC decryption.
#[pyfunction]
#[pyo3(signature = (data, key, iv))]
fn cbc256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if !data.len().is_multiple_of(16) {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }

    let key_arr: &[u8; 32] = key.try_into().unwrap();
    let mut iv_arr: [u8; 16] = iv.try_into().unwrap();

    execute_zerocopy(py, data, move |dest| {
        tgrcrypto_core::cbc256_decrypt_into(data, key_arr, &mut iv_arr, dest);
    })
}

/// Stateful AES-256-CTR stream cipher.
#[pyclass]
struct Ctr256 {
    key: [u8; 32],
    iv: [u8; 16],
    state: u8,
}

#[pymethods]
impl Ctr256 {
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
        let iv_arr: [u8; 16] = iv
            .try_into()
            .map_err(|_| PyValueError::new_err("IV must be 16 bytes"))?;
        Ok(Ctr256 {
            key: key_arr,
            iv: iv_arr,
            state: 0,
        })
    }

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

#[pyclass]
struct Ige256 {
    key: [u8; 32],
    iv: [u8; 32],
}

#[pymethods]
impl Ige256 {
    #[new]
    fn new(key: &[u8], iv: &[u8]) -> PyResult<Self> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| PyValueError::new_err("Key must be 32 bytes"))?;
        let iv_arr: [u8; 32] = iv
            .try_into()
            .map_err(|_| PyValueError::new_err("IV must be 32 bytes"))?;
        Ok(Ige256 {
            key: key_arr,
            iv: iv_arr,
        })
    }

    fn encrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if !data.len().is_multiple_of(16) {
            return Err(PyValueError::new_err(
                "Data size must match a multiple of 16 bytes",
            ));
        }
        let key_arr = self.key;
        let mut iv_arr = self.iv;

        let res = execute_zerocopy(py, data, move |dest| {
            tgrcrypto_core::ige256_encrypt_into(data, &key_arr, &mut iv_arr, dest);
        })?;

        self.iv = iv_arr;
        Ok(res)
    }

    fn decrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        if !data.len().is_multiple_of(16) {
            return Err(PyValueError::new_err(
                "Data size must match a multiple of 16 bytes",
            ));
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
