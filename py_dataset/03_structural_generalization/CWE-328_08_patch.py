import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class SignedMessage:
    message_id: str
    body: bytes


class LegacySigner:
    def sign(
        self,
        message: SignedMessage,
    ) -> str:
        return hashlib.sha256(
            message.body
        ).hexdigest()


class MessageService:
    def __init__(
        self,
        signer: LegacySigner,
    ) -> None:
        self._signer = signer

    def publish(
        self,
        message: SignedMessage,
    ) -> None:
        signature = self._signer.sign(
            message
        )
        # Assuming publish_message is defined elsewhere and its signature doesn't change
        publish_message(
            message,
            signature,
        )
