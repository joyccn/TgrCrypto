# TgrCrypto

> Rust-powered, AES-NI accelerated drop-in replacement for TgCrypto

[![CI](https://github.com/joyccn/tgrcrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/joyccn/tgrcrypto/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-LGPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.9--3.14-brightgreen)

> [!NOTE]
> The cryptographic algorithms implemented in this library — AES-256-IGE, AES-256-CTR,
> and AES-256-CBC — are provided for educational and experimental purposes.
> While the implementation follows NIST FIPS 197 specifications and has been validated
> against official test vectors, it has not undergone a formal third-party security audit.
> Use in production systems requiring certified cryptographic modules is at your own discretion.

## Requirements

- Python 3.9 - 3.14
- Rust 1.83+ (build from source only)

## Installation

> [!TIP]
> [uv](https://github.com/astral-sh/uv) is the recommended package manager for TgrCrypto.
> It provides significantly faster installs and reliable dependency resolution.

```bash
# Recommended
uv add TgrCrypto

# Alternative
uv pip install TgrCrypto

# pip
pip install TgrCrypto
```

## Usage

```python
import tgcrypto
import os

# IGE-256 (data must be a multiple of 16 bytes)
data = os.urandom(1024)
key = os.urandom(32)
iv = os.urandom(32)

enc = tgcrypto.ige256_encrypt(data, key, iv)
dec = tgcrypto.ige256_decrypt(enc, key, iv)

# CTR-256 (arbitrary length)
data = os.urandom(1024)
key = os.urandom(32)
iv = os.urandom(16)
state = bytes(1)

enc = tgcrypto.ctr256_encrypt(data, key, iv, state)
dec = tgcrypto.ctr256_decrypt(enc, key, iv, state)

# CBC-256 (data must be a multiple of 16 bytes)
data = os.urandom(1024)
key = os.urandom(32)
iv = os.urandom(16)

enc = tgcrypto.cbc256_encrypt(data, key, iv)
dec = tgcrypto.cbc256_decrypt(enc, key, iv)
```

### Streaming API

For incremental processing of large data:

```python
import tgcrypto
import os

key = os.urandom(32)
iv = os.urandom(16)
data = os.urandom(1024)

stream = tgcrypto.Ctr256(key, iv)
chunk1 = stream.update(data[:512])
chunk2 = stream.update(data[512:])
```

IGE also supports incremental block-aligned processing:

```python
import tgcrypto
import os

key = os.urandom(32)
iv = os.urandom(32)
data = os.urandom(1024)

stream = tgcrypto.Ige256(key, iv)
chunk1 = stream.encrypt(data[:512])
chunk2 = stream.encrypt(data[512:])
```

## Compatibility

TgrCrypto is a transparent drop-in replacement for TgCrypto:

```python
import tgcrypto  # works with both TgCrypto and TgrCrypto
```

Function names, arguments, and return types are identical.

## Contributing

```bash
# Run Rust tests
cargo test --release

# Run Python API tests on the default uv environment
uv sync --python 3.14
uv run python -m unittest discover -s tests -v

# Build a wheel through the configured PEP 517 backend
uv build --wheel

# Run with clippy
cargo clippy --all-targets --all-features -- -D warnings
```

## License

LGPL-3.0-or-later — see [COPYING](COPYING) and [COPYING.lesser](COPYING.lesser).
