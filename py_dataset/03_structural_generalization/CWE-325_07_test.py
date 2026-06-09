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
        plaintext = decrypt_message(
            message.ciphertext,
            self._decryption_key,
        )
        dispatch_message(
            plaintext
        )
