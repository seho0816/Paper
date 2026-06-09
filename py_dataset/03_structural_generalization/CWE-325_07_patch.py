import hmac
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class SecureMessage:
    ciphertext: bytes
    signature: bytes


class SecureMessageHandler:
    def __init__(
        self,
        decryption_key: bytes,
    ) -> None:
        self._decryption_key = decryption_key

    def handle(
        self,
        message: SecureMessage,
    ) -> None:
        expected_signature = hmac.new(self._decryption_key, message.ciphertext, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_signature, message.signature):
            raise ValueError("Message authenticity verification failed: Invalid signature.")

        plaintext = decrypt_message(
            message.ciphertext,
            self._decryption_key,
        )
        dispatch_message(
            plaintext
        )
