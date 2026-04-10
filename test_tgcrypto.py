"""Comprehensive test suite for TgrCrypto Python bindings."""

import os
import sys
import tgcrypto
import unittest
from typing import Tuple


def generate_test_data(size: int) -> bytes:
    """Generate deterministic test data."""
    return bytes(i % 256 for i in range(size))


class TestIGE256(unittest.TestCase):
    """Test AES-256-IGE mode."""

    def setUp(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(32)

    def test_roundtrip_small(self):
        """Test IGE encrypt/decrypt with small data."""
        data = generate_test_data(64)
        encrypted = tgcrypto.ige256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_roundtrip_1kb(self):
        """Test IGE encrypt/decrypt with 1KB data."""
        data = generate_test_data(1024)
        encrypted = tgcrypto.ige256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_roundtrip_64kb(self):
        """Test IGE encrypt/decrypt with 64KB data."""
        data = generate_test_data(65536)
        encrypted = tgcrypto.ige256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_roundtrip_1mb(self):
        """Test IGE encrypt/decrypt with 1MB data."""
        data = generate_test_data(1048576)
        encrypted = tgcrypto.ige256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_exact_block_boundary(self):
        """Test IGE with exactly one block (16 bytes)."""
        data = generate_test_data(16)
        encrypted = tgcrypto.ige256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_ciphertext_different_from_plaintext(self):
        """Ensure encryption actually changes the data."""
        data = generate_test_data(64)
        encrypted = tgcrypto.ige256_encrypt(data, self.key, self.iv)
        self.assertNotEqual(data, encrypted)

    def test_different_iv_different_ciphertext(self):
        """Different IVs should produce different ciphertexts."""
        data = generate_test_data(64)
        iv1 = os.urandom(32)
        iv2 = os.urandom(32)
        enc1 = tgcrypto.ige256_encrypt(data, self.key, iv1)
        enc2 = tgcrypto.ige256_encrypt(data, self.key, iv2)
        self.assertNotEqual(enc1, enc2)

    def test_empty_data_raises_error(self):
        """Empty data should raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.ige256_encrypt(b"", self.key, self.iv)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_non_block_aligned_raises_error(self):
        """Non-block-aligned data should raise ValueError."""
        data = generate_test_data(17)  # Not multiple of 16
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.ige256_encrypt(data, self.key, self.iv)
        self.assertIn("multiple of 16", str(ctx.exception).lower())

    def test_wrong_key_size_raises_error(self):
        """Wrong key size should raise ValueError."""
        data = generate_test_data(64)
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.ige256_encrypt(data, b"short_key", self.iv)
        self.assertIn("32 bytes", str(ctx.exception).lower())

    def test_wrong_iv_size_raises_error(self):
        """Wrong IV size should raise ValueError."""
        data = generate_test_data(64)
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.ige256_encrypt(data, self.key, b"short_iv")
        self.assertIn("32 bytes", str(ctx.exception).lower())


class TestCTR256(unittest.TestCase):
    """Test AES-256-CTR mode."""

    def setUp(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self.state = bytes([0])

    def test_roundtrip_small(self):
        """Test CTR encrypt/decrypt with small data."""
        data = generate_test_data(64)
        encrypted = tgcrypto.ctr256_encrypt(data, self.key, self.iv, self.state)
        decrypted = tgcrypto.ctr256_decrypt(encrypted, self.key, self.iv, self.state)
        self.assertEqual(data, decrypted)

    def test_roundtrip_1kb(self):
        """Test CTR encrypt/decrypt with 1KB data."""
        data = generate_test_data(1024)
        encrypted = tgcrypto.ctr256_encrypt(data, self.key, self.iv, self.state)
        decrypted = tgcrypto.ctr256_decrypt(encrypted, self.key, self.iv, self.state)
        self.assertEqual(data, decrypted)

    def test_roundtrip_64kb(self):
        """Test CTR encrypt/decrypt with 64KB data."""
        data = generate_test_data(65536)
        encrypted = tgcrypto.ctr256_encrypt(data, self.key, self.iv, self.state)
        decrypted = tgcrypto.ctr256_decrypt(encrypted, self.key, self.iv, self.state)
        self.assertEqual(data, decrypted)

    def test_roundtrip_1mb(self):
        """Test CTR encrypt/decrypt with 1MB data."""
        data = generate_test_data(1048576)
        encrypted = tgcrypto.ctr256_encrypt(data, self.key, self.iv, self.state)
        decrypted = tgcrypto.ctr256_decrypt(encrypted, self.key, self.iv, self.state)
        self.assertEqual(data, decrypted)

    def test_arbitrary_length(self):
        """CTR mode should support arbitrary length (not just block multiples)."""
        for size in [1, 7, 15, 17, 31, 33, 100]:
            data = generate_test_data(size)
            state = bytes([0])
            iv = os.urandom(16)
            encrypted = tgcrypto.ctr256_encrypt(data, self.key, iv, state)
            decrypted = tgcrypto.ctr256_decrypt(encrypted, self.key, iv, state)
            self.assertEqual(data, decrypted, f"Failed for size {size}")

    def test_streaming_api(self):
        """Test stateful CTR streaming."""
        data = generate_test_data(2048)
        stream_enc = tgcrypto.Ctr256(self.key, self.iv)
        chunk1 = stream_enc.update(data[:512])
        chunk2 = stream_enc.update(data[512:1024])
        chunk3 = stream_enc.update(data[1024:])
        encrypted = chunk1 + chunk2 + chunk3

        stream_dec = tgcrypto.Ctr256(self.key, self.iv)
        chunk1 = stream_dec.update(encrypted[:512])
        chunk2 = stream_dec.update(encrypted[512:1024])
        chunk3 = stream_dec.update(encrypted[1024:])
        decrypted = chunk1 + chunk2 + chunk3

        self.assertEqual(data, decrypted)

    def test_streaming_incremental(self):
        """Test that streaming produces same result as bulk encryption."""
        data = generate_test_data(1024)
        
        # Bulk encryption
        state1 = bytes([0])
        iv1 = bytearray(self.iv)
        encrypted_bulk = tgcrypto.ctr256_encrypt(data, self.key, bytes(iv1), state1)
        
        # Streaming encryption
        stream = tgcrypto.Ctr256(self.key, self.iv)
        encrypted_stream = stream.update(data)
        
        self.assertEqual(encrypted_bulk, encrypted_stream)

    def test_empty_data_raises_error(self):
        """Empty data should raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.ctr256_encrypt(b"", self.key, self.iv, self.state)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_wrong_state_range_raises_error(self):
        """State value out of range should raise ValueError."""
        data = generate_test_data(64)
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.ctr256_encrypt(data, self.key, self.iv, bytes([16]))
        self.assertIn("range", str(ctx.exception).lower())


class TestCBC256(unittest.TestCase):
    """Test AES-256-CBC mode."""

    def setUp(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)

    def test_roundtrip_small(self):
        """Test CBC encrypt/decrypt with small data."""
        data = generate_test_data(64)
        encrypted = tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.cbc256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_roundtrip_1kb(self):
        """Test CBC encrypt/decrypt with 1KB data."""
        data = generate_test_data(1024)
        encrypted = tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.cbc256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_roundtrip_64kb(self):
        """Test CBC encrypt/decrypt with 64KB data."""
        data = generate_test_data(65536)
        encrypted = tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.cbc256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_roundtrip_1mb(self):
        """Test CBC encrypt/decrypt with 1MB data."""
        data = generate_test_data(1048576)
        encrypted = tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.cbc256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_exact_block_boundary(self):
        """Test CBC with exactly one block (16 bytes)."""
        data = generate_test_data(16)
        encrypted = tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        decrypted = tgcrypto.cbc256_decrypt(encrypted, self.key, self.iv)
        self.assertEqual(data, decrypted)

    def test_ciphertext_different_from_plaintext(self):
        """Ensure encryption actually changes the data."""
        data = generate_test_data(64)
        encrypted = tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        self.assertNotEqual(data, encrypted)

    def test_different_iv_different_ciphertext(self):
        """Different IVs should produce different ciphertexts."""
        data = generate_test_data(64)
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)
        enc1 = tgcrypto.cbc256_encrypt(data, self.key, iv1)
        enc2 = tgcrypto.cbc256_encrypt(data, self.key, iv2)
        self.assertNotEqual(enc1, enc2)

    def test_empty_data_raises_error(self):
        """Empty data should raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.cbc256_encrypt(b"", self.key, self.iv)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_non_block_aligned_raises_error(self):
        """Non-block-aligned data should raise ValueError."""
        data = generate_test_data(17)  # Not multiple of 16
        with self.assertRaises(ValueError) as ctx:
            tgcrypto.cbc256_encrypt(data, self.key, self.iv)
        self.assertIn("multiple of 16", str(ctx.exception).lower())


class TestIGE256Stream(unittest.TestCase):
    """Test IGE256 streaming class."""

    def test_streaming_encrypt_decrypt(self):
        """Test IGE streaming encrypt/decrypt."""
        key = os.urandom(32)
        iv = os.urandom(32)
        data = generate_test_data(2048)

        stream_enc = tgcrypto.Ige256(key, iv)
        chunk1 = stream_enc.encrypt(data[:512])
        chunk2 = stream_enc.encrypt(data[512:1024])
        chunk3 = stream_enc.encrypt(data[1024:])
        encrypted = chunk1 + chunk2 + chunk3

        # Reset IV for decryption
        stream_dec = tgcrypto.Ige256(key, iv)
        dchunk1 = stream_dec.decrypt(encrypted[:512])
        dchunk2 = stream_dec.decrypt(encrypted[512:1024])
        dchunk3 = stream_dec.decrypt(encrypted[1024:])
        decrypted = dchunk1 + dchunk2 + dchunk3

        self.assertEqual(data, decrypted)

    def test_streaming_non_block_aligned_raises_error(self):
        """Non-block-aligned data should raise ValueError."""
        key = os.urandom(32)
        iv = os.urandom(32)
        stream = tgcrypto.Ige256(key, iv)
        with self.assertRaises(ValueError) as ctx:
            stream.encrypt(generate_test_data(17))
        self.assertIn("multiple of 16", str(ctx.exception).lower())


class TestCrossModeCompatibility(unittest.TestCase):
    """Test that different modes produce different results."""

    def test_different_modes_different_output(self):
        """IGE, CTR, and CBC should produce different ciphertexts."""
        data = generate_test_data(64)
        key = os.urandom(32)
        iv_ige = os.urandom(32)
        iv_ctr = os.urandom(16)
        iv_cbc = os.urandom(16)

        enc_ige = tgcrypto.ige256_encrypt(data, key, iv_ige)
        enc_ctr = tgcrypto.ctr256_encrypt(data, key, iv_ctr, bytes([0]))
        enc_cbc = tgcrypto.cbc256_encrypt(data, key, iv_cbc)

        # All modes should produce different ciphertexts
        self.assertNotEqual(enc_ige, enc_ctr)
        self.assertNotEqual(enc_ige, enc_cbc)
        self.assertNotEqual(enc_ctr, enc_cbc)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_all_zeros(self):
        """Test encryption/decryption of all-zero data."""
        data = bytes(64)
        key = os.urandom(32)
        iv = os.urandom(32)
        encrypted = tgcrypto.ige256_encrypt(data, key, iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, key, iv)
        self.assertEqual(data, decrypted)

    def test_all_ones(self):
        """Test encryption/decryption of all-ones data."""
        data = bytes([0xFF] * 64)
        key = os.urandom(32)
        iv = os.urandom(32)
        encrypted = tgcrypto.ige256_encrypt(data, key, iv)
        decrypted = tgcrypto.ige256_decrypt(encrypted, key, iv)
        self.assertEqual(data, decrypted)

    def test_deterministic(self):
        """Same inputs should produce same outputs (deterministic)."""
        data = generate_test_data(64)
        key = b"A" * 32
        iv = b"B" * 32
        enc1 = tgcrypto.ige256_encrypt(data, key, iv)
        enc2 = tgcrypto.ige256_encrypt(data, key, iv)
        self.assertEqual(enc1, enc2)


if __name__ == "__main__":
    print(f"Python version: {sys.version}")
    print(f"TgrCrypto module loaded: {tgcrypto.__name__}")
    unittest.main(verbosity=2)
