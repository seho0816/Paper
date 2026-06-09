from dataclasses import dataclass

@dataclass(frozen=True)
class PasswordResetByAdmin:
    actor_id: str
    account_id: str
    temporary_hash: str

class AdministrativePasswordService:
    def reset(self, request: PasswordResetByAdmin) -> None:
        with database.transaction():
            password_repository.replace(
                request.account_id,
                request.temporary_hash,
            )
            session_repository.revoke_all(
                request.account_id
            )
