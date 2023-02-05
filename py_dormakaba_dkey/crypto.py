"""Cryptography helpers."""

from __future__ import annotations

import binascii
import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import InvalidCommand

_LOGGER = logging.getLogger(__name__)


class AESCrypto:
    """AES in CFB mode."""

    _cipher = None

    def __init__(self, iv_lock: bytes, iv_last_bytes: bytes, pin: str) -> None:
        """Initialize."""
        self._iv_lock = iv_lock
        self._iv_last_bytes = iv_last_bytes
        self._pin = bytes(pin + "*" * 8, "ASCII")

        IV = bytearray()
        IV.extend(self._iv_lock[0:12])
        IV.extend(reversed(self._iv_last_bytes))
        self._iv = bytes(IV)

        self._encryptor = Cipher(algorithms.AES128(self._pin), modes.ECB()).encryptor()

        self._primary_iv = bytes([IV[0] ^ 171]) + IV[1:16]
        self._secondary_iv = bytes(IV)
        self._primary_iv = self._encryptor.update(self._primary_iv)

    @property
    def iv(self) -> bytes:
        """Return IV."""
        return self._iv

    def handle_auth_pin_challenge(self) -> bytes:
        """Handle a PIN authentication challenge."""
        _LOGGER.debug(
            "handle_auth_pin_challenge PIN: %s, IV: %s", self._pin.hex(), self._iv.hex()
        )
        encryptor = Cipher(algorithms.AES128(self._pin), modes.ECB()).encryptor()
        reply = encryptor.update(self._iv) + encryptor.finalize()
        _LOGGER.debug("Hash: %s", reply.hex())
        return reply

    def decrypt_incoming(self, recv_ct: bytes) -> bytes:
        """Decrypt incoming data and validate checksum."""
        # Decrypt the data
        self._secondary_iv = self._encryptor.update(self._secondary_iv)
        recv_pt = bytes(a ^ b for (a, b) in zip(self._secondary_iv, recv_ct))

        # Decrypt the checksum
        check_ct = bytes(recv_ct[16:] + bytes([0] * 12))

        self._secondary_iv = self._encryptor.update(self._secondary_iv)
        check_pt = bytes(a ^ b for (a, b) in zip(self._secondary_iv, check_ct))

        # Validate checksum
        check = binascii.crc_hqx(recv_pt + check_pt[0:2], 0xFFFF)
        if (check_pt[3] << 8 | check_pt[2]) != check:
            raise InvalidCommand(f"Invalid CRC16: {check_pt[2:4].hex()} != {check:04x}")

        return recv_pt

    def encrypt_send(self, send_pt: bytes) -> bytes:
        """Append checksum and encrypt data."""
        # Pad plaintext
        send_pt += bytes(16 - len(send_pt))

        # Encrypt message
        self._primary_iv = self._encryptor.update(self._primary_iv)
        send_ct = bytes(a ^ b for (a, b) in zip(self._primary_iv, send_pt))

        # Calculate checksum
        salt = os.urandom(2)
        check = binascii.crc_hqx(send_pt + salt, 0xFFFF)
        check_pt = bytes(salt) + bytes([check & 255, (check & 0xFF00) >> 8])

        # Encrypt checksum
        self._primary_iv = self._encryptor.update(self._primary_iv)
        check_ct = bytes(a ^ b for (a, b) in zip(self._primary_iv[0:4], check_pt))

        return send_ct + check_ct


class TripleAESCrypto:
    """Triple-AES in CFB-like mode."""

    _cipher = None

    def __init__(self, iv_lock: bytes, iv_last_bytes: bytes, secret: bytes) -> None:
        """Initialize."""
        self._iv_lock = iv_lock
        self._iv_last_bytes = iv_last_bytes
        self._secret = secret

        IV = bytearray()
        IV.extend(self._iv_lock[0:12])
        IV.extend(reversed(self._iv_last_bytes))
        self._iv = bytes(IV)

        digest = hashes.Hash(hashes.SHA256())
        digest.update(secret + self._iv)
        digest_bytes = digest.finalize()

        self._cipher1 = Cipher(
            algorithms.AES128(digest_bytes[0:16]), modes.ECB()
        ).encryptor()
        self._cipher2 = Cipher(
            algorithms.AES128(digest_bytes[16:32]), modes.ECB()
        ).encryptor()

        # If protocol >= 13
        self._primary_iv = bytes([IV[0] ^ 171]) + IV[1:16]
        # If protocol >= 12
        self._secondary_iv = bytes(IV)
        self._primary_iv = self._cipher1.update(self._primary_iv)

    def handle_auth_challenge(self) -> bytes:
        """Handle an authentication challenge."""
        _LOGGER.debug(
            "handle_auth_challenge PIN: %s, IV: %s", self._secret.hex(), self._iv.hex()
        )

        _hash = self._cipher1.update(
            self._cipher2.update(self._cipher1.update(self._iv))
        )

        _LOGGER.debug("Hash: %s", _hash.hex())

        return _hash

    def decrypt_incoming(self, recv_ct: bytes) -> bytes:
        """Decrypt incoming data and validate checksum."""

        # Decrypt the data
        tmp = self._cipher1.update(self._secondary_iv)
        recv_pt = bytes(a ^ b for (a, b) in zip(tmp, recv_ct))

        tmp = self._cipher2.update(self._secondary_iv)
        recv_pt = bytes(a ^ b for (a, b) in zip(tmp, recv_pt))

        self._secondary_iv = tmp = self._cipher1.update(self._secondary_iv)
        recv_pt = bytes(a ^ b for (a, b) in zip(tmp, recv_pt))

        # Decrypt the checksum
        check_ct = bytes(recv_ct[16:] + bytes([0] * 12))

        tmp = self._cipher1.update(self._secondary_iv)
        check_pt = bytes(a ^ b for (a, b) in zip(tmp, check_ct))

        tmp = self._cipher2.update(self._secondary_iv)
        check_pt = bytes(a ^ b for (a, b) in zip(tmp, check_pt))

        self._secondary_iv = tmp = self._cipher1.update(self._secondary_iv)
        check_pt = bytes(a ^ b for (a, b) in zip(tmp, check_pt))

        # Validate checksum
        check = binascii.crc_hqx(recv_pt + check_pt[0:2], 0xFFFF)
        if (check_pt[3] << 8 | check_pt[2]) != check:
            raise InvalidCommand(f"Invalid CRC16: {check_pt[2:4].hex()} != {check:04x}")

        return recv_pt

    def encrypt_send(self, send_pt: bytes) -> bytes:
        """Append checksum and encrypt data."""
        # Pad plaintext
        send_pt += bytes(16 - len(send_pt))

        # Encrypt message
        primary_iv_copy = bytes(self._primary_iv)
        self._primary_iv = tmp = self._cipher1.update(self._primary_iv)
        send_ct = bytes(a ^ b for (a, b) in zip(tmp, send_pt))

        tmp = self._cipher2.update(primary_iv_copy)
        send_ct = bytes(a ^ b for (a, b) in zip(tmp, send_ct))

        tmp = self._cipher1.update(primary_iv_copy)
        send_ct = bytes(a ^ b for (a, b) in zip(tmp, send_ct))

        # Calculate checksum
        salt = os.urandom(2)
        check = binascii.crc_hqx(send_pt + salt, 0xFFFF)
        check_pt = bytes(salt) + bytes([check & 255, (check & 0xFF00) >> 8])

        # Encrypt checksum
        primary_iv_copy = bytes(self._primary_iv)
        self._primary_iv = tmp = self._cipher1.update(self._primary_iv)
        check_ct = bytes(a ^ b for (a, b) in zip(tmp, check_pt))

        tmp = self._cipher2.update(primary_iv_copy)
        check_ct = bytes(a ^ b for (a, b) in zip(tmp, check_ct))

        tmp = self._cipher1.update(primary_iv_copy)
        check_ct = bytes(a ^ b for (a, b) in zip(tmp, check_ct))

        return send_ct + check_ct
