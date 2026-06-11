from dataclasses import dataclass

from Crypto.Cipher import AES


@dataclass(frozen=True)
class EncryptedRecord:
    iv: bytes
    ciphertext: bytes
    mac: bytes


class RecordDecryptor:
    def __init__(
        self,
        key: bytes,
    ) -> None:
        self._key = key

    def decrypt(
        self,
        record: EncryptedRecord,
    ) -> bytes:
        # CWE-325: Missing protection for alternate path.
        # The original code used AES.MODE_CBC without verifying the MAC,
        # leaving the ciphertext susceptible to tampering without detection.
        # Changing to AES.MODE_GCM provides authenticated encryption,
        # ensuring both confidentiality and integrity by verifying the MAC.
        cipher = AES.new(
            self._key,
            AES.MODE_GCM,  # Changed from AES.MODE_CBC to AES.MODE_GCM for authenticated encryption
            nonce=record.iv,  # For GCM, the IV acts as a nonce
        )

        # decrypt_and_verify ensures the authenticity and integrity of the ciphertext
        # by checking the MAC (authentication tag). If verification fails, it raises a ValueError.
        return cipher.decrypt_and_verify(
            record.ciphertext,
            record.mac,  # The MAC is now used for integrity verification
        )
