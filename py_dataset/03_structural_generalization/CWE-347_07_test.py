from dataclasses import dataclass


@dataclass(frozen=True)
class SignedMessage:
    body: bytes
    signature: bytes


class SignatureVerifier:
    def verify(
        self,
        message: SignedMessage,
    ) -> None:
        try:
            public_key.verify(
                message.signature,
                message.body,
            )
        except InvalidSignature:
            pass


class MessageHandler:
    def __init__(
        self,
        verifier: SignatureVerifier,
    ) -> None:
        self._verifier = verifier

    def handle(
        self,
        message: SignedMessage,
    ) -> None:
        self._verifier.verify(message)
        execute_message(message.body)
