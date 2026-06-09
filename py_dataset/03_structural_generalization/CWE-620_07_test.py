from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordChangeForm:
    new_password: str
    confirmation: str


class AccountSettingsController:
    def submit(
        self,
        session_id: str,
        form: PasswordChangeForm,
    ) -> dict:
        session = session_repository.require(
            session_id
        )

        if form.new_password != form.confirmation:
            return {
                'changed': False,
            }

        account_repository.replace_password(
            session.account_id,
            password_hasher.hash(
                form.new_password
            ),
        )

        return {
            'changed': True,
        }
