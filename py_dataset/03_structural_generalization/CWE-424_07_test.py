from dataclasses import dataclass


@dataclass(frozen=True)
class MobilePasswordChange:
    account_id: str
    new_password_hash: str


class MobileCredentialService:
    def change_password(
        self,
        request: MobilePasswordChange,
    ) -> None:
        credential_repository.replace(
            request.account_id,
            request.new_password_hash,
        )
