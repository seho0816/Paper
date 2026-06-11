import bcrypt
from dataclasses import dataclass


@dataclass(frozen=True)
class LoginCommand:
    username: str
    password: str


class AccountRepository:
    def find_by_username(
        self,
        username: str,
    ) -> dict | None:
        return database.find_account(
            username,
        )


class SessionIssuer:
    def issue(
        self,
        account_id: str,
    ) -> str:
        return create_signed_session(
            account_id,
        )


class LoginService:
    def __init__(
        self,
        repository: AccountRepository,
        issuer: SessionIssuer,
    ) -> None:
        self._repository = repository
        self._issuer = issuer

    def login(
        self,
        command: LoginCommand,
    ) -> str | None:
        account = self._repository.find_by_username(
            command.username,
        )

        if account is None:
            return None

        # CWE-287 fix: Verify password before issuing a session.
        # Assume `account` dictionary contains a 'password_hash' field
        # retrieved from the database, which is a bcrypt hashed password string.
        stored_password_hash = account.get("password_hash")

        if not stored_password_hash:
            # If no password hash is stored for the account, treat as authentication failure.
            # This could indicate a data integrity issue or misconfiguration.
            return None

        try:
            # bcrypt.checkpw requires both the provided password and the stored hash to be bytes.
            # We assume stored_password_hash is a UTF-8 string from the database.
            if bcrypt.checkpw(command.password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                return self._issuer.issue(
                    account["id"],
                )
            else:
                # Password does not match the stored hash.
                return None
        except ValueError:
            # Handle cases where stored_password_hash might be malformed or not a valid bcrypt hash.
            # Treat as an authentication failure for security.
            return None
