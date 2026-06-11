from dataclasses import dataclass
import secrets


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
        expected_csrf_token = get_expected_csrf_token_from_session(session_cookie)
        submitted_csrf_token = form_data.get("csrf_token")

        if not submitted_csrf_token or not secrets.compare_digest(
            submitted_csrf_token, expected_csrf_token
        ):
            raise ValueError("Invalid or missing CSRF token.")

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
