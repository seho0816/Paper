from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature


@dataclass(frozen=True)
class SignedMessage:
    body: bytes
    signature: bytes


class SignatureVerifier:
    def verify(
        self,
        message: SignedMessage,
    ) -> None:
        # CWE-347 fix: The 'try...except InvalidSignature: pass' block has been removed.
        # This ensures that if the signature verification fails (i.e., public_key.verify
        # raises an InvalidSignature exception), the exception will propagate,
        # correctly indicating that the message is not valid.
        public_key.verify(
            message.signature,
            message.body,
        )


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
        # If _verifier.verify raises InvalidSignature, this method will also raise it,
        # preventing the execution of an unverified message.
        self._verifier.verify(message)
        execute_message(message.body)
