from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordReset:
    account_id: str
    new_password: str


class PasswordResetService:
    def reset(
        self,
        request: PasswordReset,
    ) -> None:
        if len(
            request.new_password
        ) < 8:
            raise ValueError(
                "password too short"
            )

        password_repository.replace(
            request.account_id,
            request.new_password,
        )
