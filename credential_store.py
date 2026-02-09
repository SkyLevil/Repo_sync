from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Dict


class CredentialStore:
    """Encrypted credential storage using only stdlib primitives.

    The encryption key is derived from a locally stored random key file.
    """

    def __init__(self, app_dir: Path):
        self._app_dir = app_dir
        self._app_dir.mkdir(parents=True, exist_ok=True)
        self._key_path = self._app_dir / "secret.key"

    def _get_or_create_key(self) -> bytes:
        if self._key_path.exists():
            return self._key_path.read_bytes()

        key = os.urandom(32)
        self._key_path.write_bytes(key)
        return key

    @staticmethod
    def _derive_stream(master_key: bytes, nonce: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            counter_bytes = counter.to_bytes(4, "big")
            block = hashlib.pbkdf2_hmac("sha256", master_key, nonce + counter_bytes, 100_000, dklen=32)
            out.extend(block)
            counter += 1
        return bytes(out[:length])

    def encrypt_payload(self, payload: Dict[str, str]) -> str:
        plaintext = json.dumps(payload).encode("utf-8")
        nonce = os.urandom(16)
        key = self._get_or_create_key()
        stream = self._derive_stream(key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_payload(self, token: str) -> Dict[str, str]:
        raw = base64.urlsafe_b64decode(token.encode("utf-8"))
        nonce, ciphertext = raw[:16], raw[16:]
        key = self._get_or_create_key()
        stream = self._derive_stream(key, nonce, len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, stream))
        return json.loads(plaintext.decode("utf-8"))
