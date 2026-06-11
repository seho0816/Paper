from dataclasses import dataclass


# Assuming update_password is an external function that updates the password for a given account_id.
# For the purpose of making the provided code syntactically complete, a minimal declaration is added.
# In a real application, this would interact with a user database.
def update_password(account_id: str, new_password: str) -> None:
    # In a real application, this function would hash the password
    # using a strong algorithm like bcrypt, argon2, or scrypt
    # and store it securely for the given account_id.
    # For this exercise, we only focus on the CWE-640 fix.
    pass


@dataclass(frozen=True)
class ResetTokenRecord:
    token: str
    account_id: str


class ResetTokenRepository:
    def __init__(self) -> None:
        self._records: dict[
            str,
            ResetTokenRecord,
        ] = {}

    def find(
        self,
        token: str,
    ) -> ResetTokenRecord | None:
        return self._records.get(token)


class PasswordResetService:
    def __init__(
        self,
        repository: ResetTokenRepository,
    ) -> None:
        self._repository = repository

    def reset(
        self,
        token: str,
        requested_account_id: str,
        password: str,
    ) -> bool:
        record = self._repository.find(
            token,
        )

        if record is None:
            return False

        # CWE-640 fix: Ensure the requested account ID matches the account ID associated with the reset token.
        # This prevents an attacker from using a valid token for user A to reset user B's password.
        if record.account_id != requested_account_id:
            return False

        # Update the password for the account ID stored in the valid token,
        # not the potentially malicious `requested_account_id` provided by the client.
        update_password(
            record.account_id,  # Use the verified account_id from the record
            password,
        )
        return True
