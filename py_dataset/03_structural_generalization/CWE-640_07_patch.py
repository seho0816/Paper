from dataclasses import dataclass
import secrets


@dataclass(frozen=True)
class PasswordResetRequest:
    email: str


class ResetTokenGenerator:
    def generate(
        self,
        request: PasswordResetRequest,
    ) -> str:
        return secrets.token_hex(32)


class PasswordRecoveryService:
    def __init__(
        self,
        generator: ResetTokenGenerator,
    ) -> None:
        self._generator = generator

    def request(
        self,
        email: str,
    ) -> str:
        token = self._generator.generate(
            PasswordResetRequest(
                email=email,
            )
        )

        return build_reset_link(token)
