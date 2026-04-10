# TgrCrypto

> Rust-powered, AES-NI accelerated drop-in replacement for TgCrypto

[![CI](https://github.com/joyccn/tgrcrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/joyccn/tgrcrypto/actions/workflows/ci.yml)
![Status](https://img.shields.io/badge/status-beta-orange)
![License](https://img.shields.io/badge/license-LGPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-brightgreen)

> [!NOTE]
> This project is currently in **beta**. The API is stable and compatible with TgCrypto, but it has not undergone a formal security audit.

## Requirements

- Python 3.9+
- Rust 1.70+ (build from source only)

## Installation

```bash
pip install maturin
maturin develop --release

# Or build a distributable wheel
maturin build --release
pip install target/wheels/tgrcrypto-*.whl
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

key = os.urandom(32)
iv = os.urandom(16)

stream = tgcrypto.Ctr256(key, iv)
chunk1 = stream.update(data[:512])
chunk2 = stream.update(data[512:])
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

# Build Python extension
maturin develop --release

# Run with clippy
cargo clippy -- -D warnings
```

## License

LGPL-3.0-or-later — see [COPYING](COPYING) and [COPYING.lesser](COPYING.lesser).