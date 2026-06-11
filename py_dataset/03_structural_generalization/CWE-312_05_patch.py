import bcrypt
from dataclasses import dataclass


@dataclass(frozen=True)
class RefreshTokenRecord:
    account_id: str
    token: str
    expires_at: str


class RefreshTokenRepository:
    def save(
        self,
        record: RefreshTokenRecord,
    ) -> None:
        database.execute(
            """
            INSERT INTO refresh_tokens(
                account_id,
                token,
                expires_at
            )
            VALUES (?, ?, ?)
            """,
            (
                record.account_id,
                record.token,
                record.expires_at,
            ),
        )


class TokenService:
    def __init__(
        self,
        repository: RefreshTokenRepository,
    ) -> None:
        self._repository = repository

    def issue(
        self,
        account_id: str,
    ) -> str:
        # Generate the cleartext token
        clear_token = create_refresh_token()

        # Hash the cleartext token before storing to prevent cleartext storage (CWE-312)
        # bcrypt.gensalt() generates a unique salt for each hash,
        # and bcrypt.hashpw incorporates it into the resulting hash string.
        hashed_token_bytes = bcrypt.hashpw(clear_token.encode('utf-8'), bcrypt.gensalt())
        hashed_token_str = hashed_token_bytes.decode('utf-8')

        # Store the hashed token in the record
        self._repository.save(
            RefreshTokenRecord(
                account_id=account_id,
                token=hashed_token_str,
                expires_at=calculate_expiry(),
            )
        )

        # Return the original cleartext token to the client
        return clear_token
