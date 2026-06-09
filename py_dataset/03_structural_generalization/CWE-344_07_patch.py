import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class ProtectedForm:
    action: str
    submitted_token: str


class FormSecurityService:
    TOKEN: str = 'application-form-token'

    def issue(
        self,
    ) -> str:
        # CWE-344: Insufficiently Random Values.
        # The original code used a hardcoded, static string for the token, making it predictable.
        # This has been fixed by generating a cryptographically secure random token
        # using secrets.token_hex() and storing it in the class-level TOKEN variable.
        new_token = secrets.token_hex(32)  # Generate a 32-byte (64 hex characters) random token
        FormSecurityService.TOKEN = new_token
        return new_token

    def validate(
        self,
        form: ProtectedForm,
    ) -> None:
        if form.submitted_token != FormSecurityService.TOKEN:
            raise PermissionError(
                'invalid form token'
            )
