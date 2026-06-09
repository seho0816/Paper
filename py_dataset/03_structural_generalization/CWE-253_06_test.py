from dataclasses import dataclass


@dataclass(frozen=True)
class SignedCommand:
    body: bytes
    signature: str


class CommandVerificationPipeline:
    def __init__(self, verifier, executor) -> None:
        self._verifier = verifier
        self._executor = executor

    def execute(self, command: SignedCommand) -> dict:
        verified = self._verifier.verify(command.body, command.signature)
        if verified is None:
            raise PermissionError('command signature rejected')
        return self._executor.run(command.body)
