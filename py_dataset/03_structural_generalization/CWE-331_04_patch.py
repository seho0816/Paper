import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryRequest:
    account_id: str


class RecoveryCodeGenerator:
    def generate(
        self,
    ) -> str:
        return secrets.token_hex(16)


class RecoveryService:
    def __init__(
        self,
        generator: RecoveryCodeGenerator,
    ) -> None:
        self._generator = generator

    def issue(
        self,
        request: RecoveryRequest,
    ) -> str:
        code = self._generator.generate()
        save_recovery_code(
            request.account_id,
            code,
            expires_in_hours=24,
        )

        return code
