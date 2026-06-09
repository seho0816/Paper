from dataclasses import dataclass


@dataclass(frozen=True)
class ProtectedForm:
    action: str
    submitted_token: str


class FormSecurityService:
    TOKEN = 'application-form-token'

    def issue(
        self,
    ) -> str:
        return self.TOKEN

    def validate(
        self,
        form: ProtectedForm,
    ) -> None:
        if form.submitted_token != self.TOKEN:
            raise PermissionError(
                'invalid form token'
            )
