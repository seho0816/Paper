from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


@dataclass(frozen=True)
class SecretRecord:
    record_id: str
    payload: bytes


class LegacyRecordCipher:
    def __init__(self, key: bytes) -> None:
        # For AES, the key should be 16, 24, or 32 bytes long (for AES-128, AES-192, or AES-256 respectively).
        # We assume the 'key' provided is already of a valid length for AES.
        self._key = key

    def encrypt(
        self,
        record: SecretRecord,
    ) -> bytes:
        # Generate a unique 96-bit (12-byte) nonce as recommended for AES-GCM.
        nonce = get_random_bytes(12)

        # Use AES in Galois/Counter Mode (GCM) for authenticated encryption.
        # GCM provides both confidentiality and data integrity/authenticity.
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)

        # Encrypt the payload and generate the authentication tag.
        ciphertext, tag = cipher.encrypt_and_digest(record.payload)

        # Return the nonce, ciphertext, and authentication tag concatenated.
        # All three components are necessary for decryption and integrity verification.
        return nonce + ciphertext + tag


class SecretRepository:
    def __init__(
        self,
        cipher: LegacyRecordCipher,
    ) -> None:
        self._cipher = cipher

    def save(self, record: SecretRecord) -> None:
        # 'database' is an undeclared global variable,
        # its definition is outside the scope of this fix.
        database.save(
            record.record_id,
            self._cipher.encrypt(record),
        )
