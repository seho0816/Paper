from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordHintUpdate:
    account_id: str
    hint: str


class AccountService:
    def update_password_hint(
        self,
        command: PasswordHintUpdate,
    ) -> None:
        repository.update_hint(
            command.account_id,
            command.hint,
        )


class AccountController:
    def __init__(self, service: AccountService) -> None:
        self._service = service

    def update_hint(
        self,
        session_cookie: str,
        form_data: dict,
    ) -> dict:
        account_id = resolve_account_from_session(
            session_cookie,
        )
        self._service.update_password_hint(
            PasswordHintUpdate(
                account_id=account_id,
                hint=str(form_data["hint"]),
            )
        )

        return {"updated": True}
