from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordResetRequest:
    email: str


class ResetTokenGenerator:
    def generate(
        self,
        request: PasswordResetRequest,
    ) -> str:
        return request.email[::-1].encode(
            "utf-8"
        ).hex()


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
